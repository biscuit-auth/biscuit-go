package samples

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestSample1_Basic(t *testing.T) {
	token := loadSampleToken(t, "test1_basic.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	pubkey := loadRootPublicKey(t)

	verifier, err := b.Verify(pubkey)
	require.NoError(t, err)

	verifier.AddOperation("read")
	verifier.AddResource("file1")
	require.NoError(t, verifier.Verify())

	verifier.Reset()
	verifier.AddOperation("read")
	verifier.AddResource("file2")
	require.NoError(t, verifier.Verify())

	verifier.Reset()
	verifier.AddOperation("write")
	verifier.AddResource("file1")
	require.Error(t, verifier.Verify())

	s, err := b.Serialize()
	require.NoError(t, err)
	require.Equal(t, len(token), len(s))
}

func TestSample2_DifferentRootKey(t *testing.T) {
	token, err := ioutil.ReadFile("test2_different_root_key.bc")
	require.NoError(t, err)

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.Equal(t, biscuit.ErrUnknownPublicKey, err)
	require.Nil(t, v)
}

func TestSample3_InvalidSignatureFormat(t *testing.T) {
	token, err := ioutil.ReadFile("test3_invalid_signature_format.bc")
	require.NoError(t, err)

	b, err := biscuit.Unmarshal(token)
	require.Equal(t, sig.ErrInvalidZSize, err)
	require.Nil(t, b)
}

func TestSample4_RandomBlock(t *testing.T) {
	token, err := ioutil.ReadFile("test4_random_block.bc")
	require.NoError(t, err)

	_, err = biscuit.Unmarshal(token)
	require.Equal(t, sig.ErrInvalidSignature, err)
}

func TestSample5_InvalidSignature(t *testing.T) {
	token := loadSampleToken(t, "test5_invalid_signature.bc")

	b, err := biscuit.Unmarshal(token)
	require.Equal(t, sig.ErrInvalidSignature, err)
	require.Nil(t, b)
}

func TestSample6_ReorderedBlocks(t *testing.T) {
	token := loadSampleToken(t, "test6_reordered_blocks.bc")

	_, err := biscuit.Unmarshal(token)
	require.Equal(t, biscuit.ErrInvalidBlockIndex, err)
}

func TestSample7_InvalidBlockFactAuthority(t *testing.T) {
	token := loadSampleToken(t, "test7_invalid_block_fact_authority.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	_, err = b.Verify(loadRootPublicKey(t))
	require.Equal(t, biscuit.ErrInvalidBlockFact, err)
}

func TestSample8_InvalidBlockFactAmbient(t *testing.T) {
	token := loadSampleToken(t, "test8_invalid_block_fact_ambient.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	_, err = b.Verify(loadRootPublicKey(t))
	require.Equal(t, biscuit.ErrInvalidBlockFact, err)
}

func TestSample9_ExpiredToken(t *testing.T) {
	token := loadSampleToken(t, "test9_expired_token.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	v.AddOperation("read")
	v.AddResource("file1")
	v.SetTime(time.Now())
	require.Error(t, v.Verify())

	v.Reset()
	expireTime, err := time.Parse(time.RFC3339, "2018-12-20T01:00:00+01:00")
	require.NoError(t, err)

	v.AddOperation("read")
	v.AddResource("file1")
	v.SetTime(expireTime)
	require.NoError(t, v.Verify())
}

func TestSample10_AuthorityRules(t *testing.T) {
	token := loadSampleToken(t, "test10_authority_rules.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	v.AddOperation("read")
	v.AddResource("file1")
	v.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "owner",
			IDs: []biscuit.Atom{
				biscuit.Symbol("ambient"),
				biscuit.Symbol("alice"),
				biscuit.String("file1"),
			},
		},
	})
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddOperation("read")
	v.AddOperation("write")
	v.AddResource("file1")
	v.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "owner",
			IDs: []biscuit.Atom{
				biscuit.Symbol("ambient"),
				biscuit.Symbol("alice"),
				biscuit.String("file1"),
			},
		},
	})
	require.NoError(t, v.Verify())
}

func loadSampleToken(t *testing.T, path string) []byte {
	token, err := ioutil.ReadFile(path)
	require.NoError(t, err)

	return token
}

func loadRootPublicKey(t *testing.T) sig.PublicKey {
	pk, err := ioutil.ReadFile("root_key.pub")
	require.NoError(t, err)
	pubkey, err := sig.NewPublicKey(pk)
	require.NoError(t, err)

	return pubkey
}
