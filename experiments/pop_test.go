package experiments

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

// The server knows the user public key, and wants them to sign
// something, in order to prove they hold the matching private key.
//
// Signature flow overview:
//
// ---- server generates a token to be signed ----
//
// server adds:
// - facts:
//     - should_sign(#authority, dataID, alg, pubkey)
//     - data(#authority, dataID, staticCtx | challenge[16])
// - caveat:
//     - *valid(0?)<- should_sign(#authority, $0, $1, $2), valid_signature(#ambient, $0, $1, $2)
//
// ---- server sends the token to the client ----
//
// client queries for:
//     - *to_sign(dataID, $0, $1) <- should_sign(#authority, $0, $1, pubkey), data(#authority, $0, $2)
// with:
//     $0: dataID
//     $1: alg
//     $2: data
//
// foreach to_sign facts:
//     - verify data starts with staticCtx
//     - let tokenHash = Sha256(authorityBlock | all blocks | all keys)
//     - let signerNonce = random(16)
//     - let signerTimestamp = format(now, RFC3339)
//     - let signature = sign(alg, data | tokenHash | signerNonce | signerTimestamp)
//     - add fact: signature(dataID, pubkey, signature, signerNonce, signerTimestamp)
//
// ---- client sends the token to the server ----
//
// server queries for:
//     - *to_validate($0, $1, $2, $3, $4, $5, $6) <-
//         should_sign(#authority, $0, $1, $2),
//         data(#authority, $0, $3),
//         signature($0, $2, $4, $5, $6)
// with:
//     $0: dataID
//     $1: alg
//     $2: pubkey
//     $3: data
//     $4: signature
//     $5: signerNonce
//     $6: signerTimestamp
//
// foreach to_validate facts:
//     - let tokenHash = Sha256(authorityBlock | all blocks expect the last one | all keys except the last one)
//     - if nonceStore.get(signerNonce) || signerTimestamp < now - nonceWindow || signerTimestamp > now + maxClockSkew
//         - return ErrReplay
//     - verify(alg, pubkey, data | tokenHash | signerNonce | signerTimestamp, signature)
//     - if verify succeeds
//         - add ambient fact: valid_signature(#ambient, dataID, alg, pubkey)
//         - nonceStore.set(signerNonce, signerTimestamp)
//
// call verifier.verify(), if it succeeds, it means the client holds the private key.
//
// Note that the nonceStore related code and anti-replay checks are omitted from the sample below.
// The signerTimestamp allows only storing anti-replay nonces that are within a recent window of time,
// as long as timestamps outside that window are rejected.
//
func TestProofOfPossession(t *testing.T) {
	// The pubkey is known to the server, and the privkey held by the client
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The server sets up the facts allowing the client to know a signature
	// is needed, and which alg / key / data they should use.
	token, rootPubKey := getServerToken(t, pubkey)

	// Client will check for should_sign facts, and generate
	// matching signature facts containing the signed data
	token = clientSign(t, rootPubKey, pubkey, privkey, token)

	// The verifier will extract "signature" fact added by the client
	// verify it against the authority "should_sign" fact from the server
	// and add the "valid_signature" fact when matching
	// thus satisfying the authority caveat.
	verifySignature(t, rootPubKey, token)
}

var signStaticCtx = []byte("biscuit-pop-v0")

func getServerToken(t *testing.T, pubkey ed25519.PublicKey) ([]byte, sig.PublicKey) {
	rng := rand.Reader
	serverKey := sig.GenerateKeypair(rng)

	builder := biscuit.NewBuilder(serverKey)

	// add "should_sign(#authority, dataID, alg, pubkey)" fact requesting the client sign the data
	// with specified alg and the matching private key
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "should_sign",
		IDs: []biscuit.Atom{
			biscuit.Integer(0),
			biscuit.Symbol("ed25519"),
			biscuit.Bytes(pubkey),
		},
	}})

	challenge := make([]byte, 16)
	_, err := rng.Read(challenge)
	require.NoError(t, err)

	// add "data(#authority, dataID, content)" fact holding the data to be signed
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "data",
		IDs: []biscuit.Atom{
			biscuit.Integer(0),
			biscuit.Bytes(append(signStaticCtx, challenge...)),
		},
	}})

	// This caveat requires every "should_sign" fact to have a matching "valid_signature" fact,
	// that can only provided by the verifier (due to the ambient tag)
	// *valid(0?)<- should_sign(#authority, $0, $1, $2), valid_signature(#ambient, $0, $1, $2)
	builder.AddAuthorityCaveat(biscuit.Caveat{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "valid", IDs: []biscuit.Atom{biscuit.Variable(0)}},
			Body: []biscuit.Predicate{
				{Name: "should_sign", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
				{Name: "valid_signature", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
			},
		},
	}})

	b, err := builder.Build()
	require.NoError(t, err)

	t.Logf("server generated biscuit:\n%s", b.String())

	s, err := b.Serialize()
	require.NoError(t, err)
	return s, serverKey.Public()
}

func clientSign(t *testing.T, rootPubkey sig.PublicKey, pubkey ed25519.PublicKey, privkey ed25519.PrivateKey, b []byte) []byte {
	token, err := biscuit.Unmarshal(b)
	require.NoError(t, err)

	verifier, err := token.Verify(rootPubkey)
	require.NoError(t, err)

	t.Logf("clientSign world:\n%s", verifier.PrintWorld())

	// This query returns to_sign(dataID, alg, data) facts which require a signature with a private key matching pubkey.
	// in this example: [to_sign(0, "ed25519", "hex:7369676e2074686973")]
	toSign, err := verifier.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "to_sign", IDs: []biscuit.Atom{biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(1), biscuit.Bytes(pubkey)}},
			{Name: "data", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(2)}},
		},
	})
	require.NoError(t, err)
	t.Logf("toSign:\n%#v", toSign)
	require.Equal(t, 1, len(toSign))

	// Extract data from the fact
	dataID, ok := toSign[0].IDs[0].(biscuit.Integer)
	require.True(t, ok)
	alg, ok := toSign[0].IDs[1].(biscuit.Symbol)
	require.True(t, ok)
	data, ok := toSign[0].IDs[2].(biscuit.Bytes)
	require.True(t, ok)

	// confirm that the data we're signing has the static context bytes to prevent key misuse,
	// otherwise we could inadvertently sign something we didn't intend to.
	require.True(t, bytes.HasPrefix(data, signStaticCtx))

	// We have a "to_sign" fact, so we check if the token doesn't already hold a signature:
	alreadySigned, err := verifier.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "already_signed", IDs: []biscuit.Atom{biscuit.Variable(0)}},
		Body: []biscuit.Predicate{
			{Name: "signature", IDs: []biscuit.Atom{dataID, biscuit.Bytes(pubkey), biscuit.Variable(0)}},
		},
	})
	require.NoError(t, err)
	t.Logf("already signed:\n%#v", alreadySigned)
	require.Equal(t, 0, len(alreadySigned))

	signerTimestamp := time.Now()
	signerNonce := make([]byte, 16)
	_, err = rand.Read(signerNonce)
	require.NoError(t, err)

	tokenHash, err := token.SHA256Sum(token.BlockCount())
	require.NoError(t, err)

	dataToSign := append(data, tokenHash...)
	dataToSign = append(dataToSign, signerNonce...)
	dataToSign = append(dataToSign, []byte(signerTimestamp.Format(time.RFC3339))...)

	// Sign the data
	var signedData biscuit.Bytes
	switch alg {
	case "ed25519":
		signedData = ed25519.Sign(privkey, dataToSign)
	default:
		t.Fatalf("unsupported alg: %s", alg)
	}

	// Add the signature to the token
	builder := token.CreateBlock()

	err = builder.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "signature",
		// Add back the pubkey so we can have multiple signatures across the same data
		// + the anti replay nonce and timestamp
		IDs: []biscuit.Atom{dataID, biscuit.Bytes(pubkey), signedData, biscuit.Bytes(signerNonce), biscuit.Date(signerTimestamp)},
	}})
	require.NoError(t, err)

	rng := rand.Reader
	clientKey := sig.GenerateKeypair(rng)
	token, err = token.Append(rng, clientKey, builder.Build())
	require.NoError(t, err)

	t.Logf("final client biscuit:\n%s", token.String())

	s, err := token.Serialize()
	require.NoError(t, err)

	return s
}

func verifySignature(t *testing.T, rootPubKey sig.PublicKey, b []byte) {
	token, err := biscuit.Unmarshal(b)
	require.NoError(t, err)

	verifier, err := token.Verify(rootPubKey)
	require.NoError(t, err)

	t.Logf("verifySignature world before:\n%s", verifier.PrintWorld())

	// Generate "to_validate(dataID, alg, pubkey, data, signerNonce, signerTimestamp, signature)" facts from existing signatures
	toValidate, err := verifier.Query(biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "to_validate",
			IDs: []biscuit.Atom{
				biscuit.Variable(0), // dataID
				biscuit.Variable(1), // alg
				biscuit.Variable(2), // pubkey
				biscuit.Variable(3), // data
				biscuit.Variable(4), // signature
				biscuit.Variable(5), // signerNonce
				biscuit.Variable(6), // signerTimestamp
			}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
			{Name: "data", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(3)}},
			{Name: "signature", IDs: []biscuit.Atom{biscuit.Variable(0), biscuit.Variable(2), biscuit.Variable(4), biscuit.Variable(5), biscuit.Variable(6)}},
		},
	})
	require.NoError(t, err)
	t.Logf("to validate:\n%s", toValidate)
	require.Equal(t, 1, len(toValidate))

	// Extract data from the fact
	dataID, ok := toValidate[0].IDs[0].(biscuit.Integer)
	require.True(t, ok)
	alg, ok := toValidate[0].IDs[1].(biscuit.Symbol)
	require.True(t, ok)
	pubkey, ok := toValidate[0].IDs[2].(biscuit.Bytes)
	require.True(t, ok)
	data, ok := toValidate[0].IDs[3].(biscuit.Bytes)
	require.True(t, ok)
	signature, ok := toValidate[0].IDs[4].(biscuit.Bytes)
	require.True(t, ok)
	signerNonce, ok := toValidate[0].IDs[5].(biscuit.Bytes)
	require.True(t, ok)
	signerTimestamp, ok := toValidate[0].IDs[6].(biscuit.Date)
	require.True(t, ok)

	// retrieve the block index containing user signature
	blockIdx, err := verifier.Biscuit().GetBlockID(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "signature",
		IDs:  []biscuit.Atom{dataID, pubkey, signature, signerNonce, signerTimestamp},
	}})
	require.NoError(t, err)
	// the signedTokenHash is on all the blocks before the one containing the signature.
	signedTokenHash, err := token.SHA256Sum(blockIdx - 1)
	require.NoError(t, err)

	// Reconstruct signed data with all the above properties
	signedData := append(data, signedTokenHash...)
	signedData = append(signedData, signerNonce...)
	signedData = append(signedData, []byte(time.Time(signerTimestamp).Format(time.RFC3339))...)

	validSignature := false
	switch alg {
	case "ed25519":
		validSignature = ed25519.Verify(ed25519.PublicKey(pubkey), signedData, signature)
	default:
		t.Fatalf("unsupported alg: %s", alg)
	}
	require.True(t, validSignature)

	verifier.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "valid_signature",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), dataID, alg, pubkey},
	}})

	t.Logf("verifySignature world after:\n%s", verifier.PrintWorld())
	require.NoError(t, verifier.Verify())
}
