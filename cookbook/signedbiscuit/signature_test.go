package signedbiscuit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/stretchr/testify/require"
)

func TestUserSignVerify(t *testing.T) {
	tokenHash := make([]byte, 32)
	_, err := rand.Read(tokenHash)
	require.NoError(t, err)

	challenge := make([]byte, challengeSize)
	_, err = rand.Read(challenge)
	require.NoError(t, err)

	userKey := generateUserKeyPair(t)

	toSignData := &userToSignData{
		DataID: 1,
		Alg:    biscuit.Symbol(ECDSA_P256_SHA256),
		Data:   []byte("challenge"),
	}

	signedData, err := userSign(tokenHash, userKey, toSignData)
	require.NoError(t, err)
	require.NotEmpty(t, signedData.Signature)
	require.Equal(t, biscuit.Integer(1), signedData.DataID)
	require.Equal(t, biscuit.Bytes(userKey.Public), signedData.UserPubKey)

	require.Len(t, signedData.Nonce, nonceSize)
	zeroNonce := make([]byte, nonceSize)
	require.NotEqual(t, biscuit.Bytes(zeroNonce), signedData.Nonce)

	require.WithinDuration(t, time.Now(), time.Time(signedData.Timestamp), 1*time.Second)

	require.NoError(t, verifyUserSignature(tokenHash, &userVerificationData{
		DataID:     toSignData.DataID,
		Alg:        toSignData.Alg,
		Data:       toSignData.Data,
		Nonce:      signedData.Nonce,
		Signature:  signedData.Signature,
		Timestamp:  signedData.Timestamp,
		UserPubKey: signedData.UserPubKey,
	}))
}

func TestUserSignFail(t *testing.T) {
	validTokenHash := make([]byte, 32)
	_, err := rand.Read(validTokenHash)
	require.NoError(t, err)

	validChallenge := make([]byte, challengeSize)
	_, err = rand.Read(validChallenge)
	require.NoError(t, err)

	invalidPrivateKey := &UserKeyPair{
		Private: make([]byte, 32),
	}

	testCases := []struct {
		desc        string
		tokenHash   []byte
		userKey     *UserKeyPair
		data        *userToSignData
		expectedErr error
	}{
		{
			desc:      "empty tokenHash",
			tokenHash: []byte{},
		},
		{
			desc:      "unsupported alg",
			tokenHash: validTokenHash,
			data: &userToSignData{
				Alg: "unsupported",
			},
			expectedErr: ErrUnsupportedSignatureAlg,
		},
		{
			desc:      "wrong private key encoding",
			tokenHash: validTokenHash,
			data: &userToSignData{
				Alg: biscuit.Symbol(ECDSA_P256_SHA256),
			},
			userKey: invalidPrivateKey,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			_, err := userSign(testCase.tokenHash, testCase.userKey, testCase.data)
			require.Error(t, err)
			if testCase.expectedErr != nil {
				require.Equal(t, testCase.expectedErr, err)
			}
		})
	}
}

func TestVerifyUserSignatureFail(t *testing.T) {
	tokenHash := []byte("token hash")
	toSignData := &userToSignData{
		DataID: 1,
		Alg:    biscuit.Symbol(ECDSA_P256_SHA256),
		Data:   []byte("challenge"),
	}

	userKey := generateUserKeyPair(t)
	invalidKey := generateUserKeyPair(t)

	signedData, err := userSign(tokenHash, userKey, toSignData)
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	wrongKeyKind, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	testCases := []struct {
		desc        string
		tokenHash   []byte
		data        *userVerificationData
		expectedErr error
	}{
		{
			desc:        "unsupported alg",
			expectedErr: ErrUnsupportedSignatureAlg,
			data: &userVerificationData{
				Alg: "unknown",
			},
		},
		{
			desc: "invalid pubkey encoding",
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: make([]byte, 32),
			},
		},
		{
			desc: "invalid pubkey kind",
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: wrongKeyKind,
			},
		},
		{
			desc:      "wrong pubkey",
			tokenHash: tokenHash,
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: invalidKey.Public,
				Data:       toSignData.Data,
				DataID:     toSignData.DataID,
				Nonce:      signedData.Nonce,
				Signature:  signedData.Signature,
				Timestamp:  signedData.Timestamp,
			},
		},
		{
			desc:        "tampered token hash",
			expectedErr: ErrInvalidSignature,
			tokenHash:   []byte("wrong"),
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: userKey.Public,
				Data:       toSignData.Data,
				DataID:     toSignData.DataID,
				Nonce:      signedData.Nonce,
				Signature:  signedData.Signature,
				Timestamp:  signedData.Timestamp,
			},
		},
		{
			desc:        "tampered nonce",
			expectedErr: ErrInvalidSignature,
			tokenHash:   tokenHash,
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: userKey.Public,
				Data:       toSignData.Data,
				DataID:     toSignData.DataID,
				Nonce:      []byte("another nonce"),
				Signature:  signedData.Signature,
				Timestamp:  signedData.Timestamp,
			},
		},
		{
			desc:        "tampered timestamp",
			expectedErr: ErrInvalidSignature,
			tokenHash:   tokenHash,
			data: &userVerificationData{
				Alg:        biscuit.Symbol(ECDSA_P256_SHA256),
				UserPubKey: userKey.Public,
				Data:       toSignData.Data,
				DataID:     toSignData.DataID,
				Nonce:      signedData.Nonce,
				Signature:  signedData.Signature,
				Timestamp:  biscuit.Date(time.Now().Add(1 * time.Second)),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			err := verifyUserSignature(testCase.tokenHash, testCase.data)
			require.Error(t, err)
			if testCase.expectedErr != nil {
				require.Equal(t, testCase.expectedErr, err)
			}
		})
	}
}

func generateUserKeyPair(t *testing.T) *UserKeyPair {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kp, err := NewECDSAKeyPair(priv)
	require.NoError(t, err)
	return kp
}
