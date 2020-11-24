package signedbiscuit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
)

type Metadata struct {
	ClientID  string
	UserID    string
	UserEmail string
	IssueTime time.Time
}

type UserKeyPair struct {
	Public  []byte
	Private []byte
}

func NewECDSAKeyPair(priv *ecdsa.PrivateKey) (*UserKeyPair, error) {
	privKeyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ecdsa privkey: %v", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ecdsa pubkey: %v", err)
	}
	return &UserKeyPair{
		Private: privKeyBytes,
		Public:  pubKeyBytes,
	}, nil
}

// WithSignableFacts returns a biscuit which will only verify after being
// signed with the private key matching the given userPubkey.
func WithSignableFacts(b biscuit.Builder, audience string, audienceKey crypto.Signer, userPublicKey []byte, expireTime time.Time, m *Metadata) (biscuit.Builder, error) {
	builder := &hubauthBuilder{
		Builder: b,
	}

	if err := builder.withAudienceSignature(audience, audienceKey); err != nil {
		return nil, err
	}

	if err := builder.withUserToSignFact(userPublicKey); err != nil {
		return nil, err
	}

	if err := builder.withExpire(expireTime); err != nil {
		return nil, err
	}

	if err := builder.withMetadata(m); err != nil {
		return nil, err
	}

	return builder.Builder, nil
}

// Sign append a user signature on the given token and return it.
// The UserKeyPair key format to provide depends on the signature algorithm:
// - for ECDSA_P256_SHA256, the private key must be encoded in SEC 1, ASN.1 DER form,
// and the public key in PKIX, ASN.1 DER form.
func Sign(token []byte, rootPubKey sig.PublicKey, userKey *UserKeyPair) ([]byte, error) {
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to unmarshal: %w", err)
	}

	v, err := b.Verify(rootPubKey)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to verify: %w", err)
	}
	verifier := &hubauthVerifier{
		Verifier: v,
	}

	toSignData, err := verifier.getUserToSignData(userKey.Public)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to get to_sign data: %w", err)
	}

	if err := verifier.ensureNotAlreadyUserSigned(toSignData.DataID, userKey.Public); err != nil {
		return nil, fmt.Errorf("biscuit: previous signature check failed: %w", err)
	}

	tokenHash, err := b.SHA256Sum(b.BlockCount())
	if err != nil {
		return nil, err
	}

	signData, err := userSign(tokenHash, userKey, toSignData)
	if err != nil {
		return nil, fmt.Errorf("biscuit: signature failed: %w", err)
	}

	builder := &hubauthBlockBuilder{
		BlockBuilder: b.CreateBlock(),
	}
	if err := builder.withUserSignature(signData); err != nil {
		return nil, fmt.Errorf("biscuit: failed to create signature block: %w", err)
	}

	clientKey := sig.GenerateKeypair(rand.Reader)
	b, err = b.Append(rand.Reader, clientKey, builder.Build())
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to append signature block: %w", err)
	}

	return b.Serialize()
}

type UserSignatureMetadata struct {
	*Metadata
	UserSignatureNonce     []byte
	UserSignatureTimestamp time.Time
}

// WithSignatureVerification prepares the given verifier in order to verify the audience and user signatures.
// The user signature metadata are returned to the caller to handle the anti replay checks, but they shouldn't be used
// before having called verifier.Verify()
func WithSignatureVerification(v biscuit.Verifier, audience string, audienceKey *ecdsa.PublicKey) (biscuit.Verifier, *UserSignatureMetadata, error) {
	verifier := &hubauthVerifier{
		Verifier: v,
	}

	audienceVerificationData, err := verifier.getAudienceVerificationData(audience)
	if err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to retrieve audience signature data: %w", err)
	}

	if err := verifyAudienceSignature(audienceKey, audienceVerificationData); err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to verify audience signature: %w", err)
	}
	if err := verifier.withValidatedAudienceSignature(audienceVerificationData); err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to add validated signature: %w", err)
	}

	userVerificationData, err := verifier.getUserVerificationData()
	if err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to retrieve user signature data: %w", err)
	}

	signatureBlockID, err := v.Biscuit().GetBlockID(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "signature",
		IDs: []biscuit.Atom{
			userVerificationData.DataID,
			userVerificationData.UserPubKey,
			userVerificationData.Signature,
			userVerificationData.Nonce,
			userVerificationData.Timestamp,
		},
	}})
	if err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to retrieve signature blockID: %w", err)
	}

	signedTokenHash, err := v.Biscuit().SHA256Sum(signatureBlockID - 1)
	if err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to generate token hash: %w", err)
	}

	if err := verifyUserSignature(signedTokenHash, userVerificationData); err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to verify user signature: %w", err)
	}
	if err := verifier.withValidatedUserSignature(userVerificationData); err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to add validated signature: %w", err)
	}

	if err := verifier.withCurrentTime(time.Now()); err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to add current time: %w", err)
	}

	metas, err := verifier.getMetadata()
	if err != nil {
		return nil, nil, fmt.Errorf("biscuit: failed to get metadata: %v", err)
	}
	return v, &UserSignatureMetadata{
		Metadata:               metas,
		UserSignatureNonce:     userVerificationData.Nonce,
		UserSignatureTimestamp: time.Time(userVerificationData.Timestamp),
	}, nil
}
