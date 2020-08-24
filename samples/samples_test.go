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

	v.Reset()
	v.AddOperation("delete")
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
	require.Error(t, v.Verify())
}

func TestSample11_VerifierAuthorityCaveats(t *testing.T) {
	token := loadSampleToken(t, "test11_verifier_authority_caveats.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	verifierCaveat := biscuit.Caveat{
		Queries: []biscuit.Rule{
			{
				Head: biscuit.Predicate{
					Name: "caveat1",
					IDs:  []biscuit.Atom{biscuit.Variable(0), biscuit.Variable(1)},
				},
				Body: []biscuit.Predicate{
					{Name: "right", IDs: []biscuit.Atom{biscuit.Symbol("authority"), biscuit.Variable(0), biscuit.Variable(1)}},
					{Name: "resource", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(0)}},
					{Name: "operation", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(1)}},
				},
			},
		},
	}

	v.AddOperation("read")
	v.AddResource("file1")
	v.AddCaveat(verifierCaveat)
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddOperation("write")
	v.AddResource("file1")
	v.AddCaveat(verifierCaveat)
	require.Error(t, v.Verify())

	v.Reset()
	v.AddOperation("read")
	v.AddResource("/another/file1")
	v.AddCaveat(verifierCaveat)
	require.Error(t, v.Verify())
}

func TestSample12_AuthorityCaveats(t *testing.T) {
	token := loadSampleToken(t, "test12_authority_caveats.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	v.AddResource("file1")
	require.NoError(t, v.Verify())

	v.AddResource("file1")
	v.AddOperation("anything")
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddResource("file2")
	require.Error(t, v.Verify())
}

func TestSample13_BlockRules(t *testing.T) {
	token := loadSampleToken(t, "test13_block_rules.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	v.AddResource("file1")
	v.SetTime(time.Now())
	require.NoError(t, v.Verify())

	file1ValidTime, err := time.Parse(time.RFC3339, "2030-12-31T12:59:59+00:00")
	require.NoError(t, err)

	v.Reset()
	v.AddResource("file1")
	v.SetTime(file1ValidTime)
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddResource("file1")
	v.SetTime(file1ValidTime.Add(1 * time.Second))
	require.Error(t, v.Verify())

	v.Reset()
	v.AddResource("file2")
	v.SetTime(time.Now())
	require.Error(t, v.Verify())

	otherFileValidTime, err := time.Parse(time.RFC3339, "1999-12-31T12:59:59+00:00")
	require.NoError(t, err)

	v.Reset()
	v.AddResource("file2")
	v.SetTime(otherFileValidTime)
	require.NoError(t, v.Verify())
}

func TestSample14_RegexConstraint(t *testing.T) {
	token := loadSampleToken(t, "test14_regex_constraint.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	validFiles := []string{
		"file1.txt",
		"file1.txt.zip",
		"file9000.txt",
		"/dir/file000.txt",
		"file000.txt/dir/",
	}

	for _, validFile := range validFiles {
		v.Reset()
		v.AddResource(validFile)
		require.NoError(t, v.Verify())
	}

	invalidFiles := []string{
		"file1",
		"fileA.txt",
		"fileA1.txt",
		"file1.zip",
	}

	for _, invalidFile := range invalidFiles {
		v.Reset()
		v.AddResource(invalidFile)
		require.Error(t, v.Verify())
	}
}

func TestSample15_MultiQueriesCaveats(t *testing.T) {
	token := loadSampleToken(t, "test15_multi_queries_caveats.bc")

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	v, err := b.Verify(loadRootPublicKey(t))
	require.NoError(t, err)

	rule1 := biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "test_must_be_present_authority",
			IDs:  []biscuit.Atom{biscuit.Variable(0)},
		},
		Body: []biscuit.Predicate{
			{Name: "must_be_present", IDs: []biscuit.Atom{biscuit.Symbol("authority"), biscuit.Variable(0)}},
		},
	}

	rule2 := biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "test_must_be_present",
			IDs:  []biscuit.Atom{biscuit.Variable(0)},
		},
		Body: []biscuit.Predicate{
			{Name: "must_be_present", IDs: []biscuit.Atom{biscuit.Variable(0)}},
		},
	}

	v.AddCaveat(biscuit.Caveat{Queries: []biscuit.Rule{rule1, rule2}})
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddCaveat(biscuit.Caveat{Queries: []biscuit.Rule{rule1}})
	require.NoError(t, v.Verify())

	v.Reset()
	v.AddCaveat(biscuit.Caveat{Queries: []biscuit.Rule{rule2}})
	require.Error(t, v.Verify())
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
