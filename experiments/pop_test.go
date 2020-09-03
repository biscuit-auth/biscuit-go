package experiments

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

// The server knows the user public key, and want him to sign
// something, in order to prove he holds the matching private key.
func TestProofOfPossession(t *testing.T) {
	// The pubkey is known to the server, and the privkey held by the client
	// We want the server to know that the client hold the privkey.
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The server setup the facts allowing the client to know a signature
	// is needed, and which alg / key / data he should use.
	token := getServerToken(t, pubkey)

	// Client will check for should_sign facts, and generate
	// matching signature facts containing the signed data
	token = clientSign(t, pubkey, privkey, token)

	// The verifier will extract "signature" fact added by the client
	// verify it against the authority "should_sign" fact from the server
	// and add the "valid_signature" fact when matching
	// thus satisfying the authority caveat.
	verifySignature(t, token)
}

func getServerToken(t *testing.T, pubkey ed25519.PublicKey) *biscuit.Biscuit {
	rng := rand.Reader
	serverKey := sig.GenerateKeypair(rng)

	builder := biscuit.NewBuilder(rng, serverKey)

	// add "should_sign(#authority, dataID, alg, pubkey)" fact requesting the client to sign the data
	// with specified alg and the matching private key
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "should_sign",
		IDs: []biscuit.Atom{
			biscuit.Integer(0),
			biscuit.Symbol("ed25519"),
			biscuit.Bytes(pubkey),
		},
	}})

	// add "data(#authority, dataID, content)" fact holding the data to be signed
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "data",
		IDs: []biscuit.Atom{
			biscuit.Integer(0),
			biscuit.Bytes([]byte("sign this")),
		},
	}})

	// This caveat requires every "should_sign" fact to have a matching "valid_signature" fact,
	// that can only provided by the verifier (due to the ambient tag)
	// *valid(0?)<- should_sign(0?, 1?, 2?), valid_signature(#ambient, $0, $1, $2)
	builder.AddAuthorityCaveat(biscuit.Rule{
		Head: biscuit.Predicate{Name: "valid", IDs: []biscuit.Atom{biscuit.Variable(0)}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
			{Name: "valid_signature", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
		},
	})

	b, err := builder.Build()
	require.NoError(t, err)

	t.Logf("server generated biscuit:\n%s", b.String())

	return b
}

func clientSign(t *testing.T, pubkey ed25519.PublicKey, privkey ed25519.PrivateKey, token *biscuit.Biscuit) *biscuit.Biscuit {
	verifier, err := biscuit.NewVerifier(token)
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

	// We have a "to_sign" fact, so we check if the token doesn't already hold a signature:
	alreadySigned, err := verifier.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "already_signed", IDs: []biscuit.Atom{biscuit.Variable(0)}},
		Body: []biscuit.Predicate{
			{Name: "signature", IDs: []biscuit.Atom{dataID, alg, biscuit.Variable(0)}},
		},
	})
	require.NoError(t, err)
	t.Logf("already signed:\n%#v", alreadySigned)
	require.Equal(t, 0, len(alreadySigned))

	// Sign the data
	var signedData biscuit.Bytes
	switch alg {
	case "ed25519":
		signedData = ed25519.Sign(privkey, data)
	default:
		t.Fatalf("unsupported alg: %s", alg)
	}

	// Add the signature to the token
	builder := token.CreateBlock()

	err = builder.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "signature",
		IDs:  []biscuit.Atom{dataID, alg /*biscuit.Bytes(pubkey),*/, signedData},
	}})
	require.NoError(t, err)
	// not sure we need to repeat the pubkey here,
	// since the one from the authority fact can be used for the verification.

	rng := rand.Reader
	clientKey := sig.GenerateKeypair(rng)
	token, err = token.Append(rng, clientKey, builder.Build())
	require.NoError(t, err)

	return token
}

func verifySignature(t *testing.T, token *biscuit.Biscuit) {
	verifier, err := biscuit.NewVerifier(token)
	require.NoError(t, err)

	t.Logf("verifySignature world before:\n%s", verifier.PrintWorld())

	// Generate "to_validate(dataID, alg, pubkey, data, signature)" facts from existing signatures
	toValidate, err := verifier.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "to_validate", IDs: []biscuit.Atom{biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2), biscuit.Variable(3), biscuit.Variable(4)}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(2)}},
			{Name: "data", IDs: []biscuit.Atom{biscuit.SymbolAuthority, biscuit.Variable(0), biscuit.Variable(3)}},
			{Name: "signature", IDs: []biscuit.Atom{biscuit.Variable(0), biscuit.Variable(1), biscuit.Variable(4)}},
		},
	})
	require.NoError(t, err)
	t.Logf("to validate:\n%#v", toValidate)
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

	validSignature := false
	switch alg {
	case "ed25519":
		validSignature = ed25519.Verify(ed25519.PublicKey(pubkey), data, signature)
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
