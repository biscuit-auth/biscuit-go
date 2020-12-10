package signedbiscuit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/biscuit-go"
)

var (
	ErrUnsupportedSignatureAlg = errors.New("unsupported signature algorithm")
	ErrInvalidSignature        = errors.New("invalid signature")
)

type SignatureAlg biscuit.Symbol

const (
	ECDSA_P256_SHA256 SignatureAlg = "ECDSA_P256_SHA256"
)

type userToSignData struct {
	DataID biscuit.Integer
	Alg    biscuit.Symbol
	Data   biscuit.Bytes
}

type userSignatureData struct {
	DataID     biscuit.Integer
	UserPubKey biscuit.Bytes
	Signature  biscuit.Bytes
	Nonce      biscuit.Bytes
	Timestamp  biscuit.Date
}

type userVerificationData struct {
	DataID     biscuit.Integer
	Alg        biscuit.Symbol
	Data       biscuit.Bytes
	UserPubKey biscuit.Bytes
	Signature  biscuit.Bytes
	Nonce      biscuit.Bytes
	Timestamp  biscuit.Date
}

func userSign(tokenHash []byte, userKey *UserKeyPair, toSignData *userToSignData) (*userSignatureData, error) {
	if len(tokenHash) == 0 {
		return nil, errors.New("invalid tokenHash")
	}

	signerTimestamp := time.Now()
	signerNonce := make([]byte, nonceSize)
	if _, err := rand.Read(signerNonce); err != nil {
		return nil, err
	}

	var dataToSign []byte
	dataToSign = append(dataToSign, toSignData.Data...)
	dataToSign = append(dataToSign, tokenHash...)
	dataToSign = append(dataToSign, signerNonce...)
	dataToSign = append(dataToSign, []byte(signerTimestamp.Format(time.RFC3339))...)

	var signedData biscuit.Bytes
	switch SignatureAlg(toSignData.Alg) {
	case ECDSA_P256_SHA256:
		privKey, err := x509.ParseECPrivateKey(userKey.Private)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(dataToSign)
		signedData, err = ecdsa.SignASN1(rand.Reader, privKey, hash[:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedSignatureAlg
	}

	return &userSignatureData{
		DataID:     toSignData.DataID,
		Nonce:      signerNonce,
		Signature:  signedData,
		Timestamp:  biscuit.Date(signerTimestamp),
		UserPubKey: userKey.Public,
	}, nil
}

func verifyUserSignature(signedTokenHash []byte, data *userVerificationData) error {
	var signedData []byte
	signedData = append(signedData, data.Data...)
	signedData = append(signedData, signedTokenHash...)
	signedData = append(signedData, data.Nonce...)
	signedData = append(signedData, []byte(time.Time(data.Timestamp).Format(time.RFC3339))...)

	switch SignatureAlg(data.Alg) {
	case ECDSA_P256_SHA256:
		pk, err := x509.ParsePKIXPublicKey(data.UserPubKey)
		if err != nil {
			return err
		}
		pubkey, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid pubkey, not an *ecdsa.PublicKey")
		}

		hash := sha256.Sum256(signedData)
		if !ecdsa.VerifyASN1(pubkey, hash[:], data.Signature) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return ErrUnsupportedSignatureAlg
	}
}

type audienceVerificationData struct {
	Audience  biscuit.Symbol
	Challenge biscuit.Bytes
	Signature biscuit.Bytes
}

func audienceSign(audience string, audienceKey crypto.Signer) (*audienceVerificationData, error) {
	challenge := make([]byte, challengeSize)
	if _, err := rand.Reader.Read(challenge); err != nil {
		return nil, err
	}

	signedData := append(signStaticCtx, challenge...)
	signedData = append(signedData, []byte(audience)...)
	signedHash := sha256.Sum256(signedData)
	signature, err := audienceKey.Sign(rand.Reader, signedHash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &audienceVerificationData{
		Audience:  biscuit.Symbol(audience),
		Challenge: challenge,
		Signature: signature,
	}, nil
}

func verifyAudienceSignature(audiencePubkey *ecdsa.PublicKey, data *audienceVerificationData) error {
	signedData := append(signStaticCtx, data.Challenge...)
	signedData = append(signedData, []byte(data.Audience)...)
	hash := sha256.Sum256(signedData)

	if !ecdsa.VerifyASN1(audiencePubkey, hash[:], data.Signature) {
		return errors.New("invalid signature")
	}
	return nil
}

func validatePKIXP256PublicKey(pubkey []byte) error {
	key, err := x509.ParsePKIXPublicKey(pubkey)
	if err != nil {
		return fmt.Errorf("failed to parse PKIX, ASN.1 DER public key: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not an *ecdsa.PublicKey")
	}

	if ecKey.Curve != elliptic.P256() {
		return fmt.Errorf("publickey is on wrong curve, expected P256")
	}

	return nil
}
