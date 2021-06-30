package signedbiscuit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestBiscuit(t *testing.T) {
	rootKey := sig.GenerateKeypair(rand.Reader)
	audience := "http://random.audience.url"

	audienceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	userKey := generateUserKeyPair(t)
	metas := &Metadata{
		ClientID:   "abcd",
		UserEmail:  "1234@example.com",
		UserID:     "1234",
		UserGroups: []string{"grp1", "grp2"},
		IssueTime:  time.Now(),
	}

	builder := biscuit.NewBuilder(rootKey)

	builder, err = WithSignableFacts(builder, audience, audienceKey, userKey.Public, time.Now().Add(5*time.Minute), metas)
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)
	signableBiscuit, err := b.Serialize()
	require.NoError(t, err)
	t.Logf("signable biscuit size: %d", len(signableBiscuit))

	t.Run("happy path", func(t *testing.T) {
		signedBiscuit, err := Sign(signableBiscuit, rootKey.Public(), userKey)
		require.NoError(t, err)
		t.Logf("signed biscuit size: %d", len(signedBiscuit))

		b, err := biscuit.Unmarshal(signedBiscuit)
		require.NoError(t, err)
		verifier, err := b.Verify(rootKey.Public())
		require.NoError(t, err)

		verifier, res, err := WithSignatureVerification(verifier, audience, audienceKey.Public().(*ecdsa.PublicKey))
		require.NoError(t, verifier.Verify())

		require.NoError(t, err)
		require.Equal(t, metas.ClientID, res.ClientID)
		require.Equal(t, metas.UserID, res.UserID)
		require.Equal(t, metas.UserEmail, res.UserEmail)
		require.Equal(t, metas.UserGroups, res.UserGroups)
		require.WithinDuration(t, metas.IssueTime, res.IssueTime, 1*time.Second)
		require.NotEmpty(t, res.UserSignatureNonce)
		require.NotEmpty(t, res.UserSignatureTimestamp)
	})

	t.Run("user sign with wrong key", func(t *testing.T) {
		_, err := Sign(signableBiscuit, rootKey.Public(), generateUserKeyPair(t))
		require.Error(t, err)
	})

	t.Run("verify wrong audience", func(t *testing.T) {
		signedBiscuit, err := Sign(signableBiscuit, rootKey.Public(), userKey)
		require.NoError(t, err)

		b, err := biscuit.Unmarshal(signedBiscuit)
		require.NoError(t, err)
		verifier, err := b.Verify(rootKey.Public())
		require.NoError(t, err)

		_, _, err = WithSignatureVerification(verifier, "http://another.audience.url", audienceKey.Public().(*ecdsa.PublicKey))
		require.Error(t, err)

		wrongAudienceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, _, err = WithSignatureVerification(verifier, audience, wrongAudienceKey.Public().(*ecdsa.PublicKey))
		require.Error(t, err)
	})
}
