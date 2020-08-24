package sig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// The first 384 bytes from SeedableRng::seed_from_u64(0) so that we can test against biscuit-rust vectors
var rustRngBytes, _ = hex.DecodeString("b2f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f58a28c18576b71e5e61c32867855a03cd0a8c91e731f9a1c00a6c0870d9d2e40e4dc580e2f621a7ffa4541a7dffa5cc5a3c78dacf4a7c74364b12384f8d6ca16e9e9a8532b0c9725bc870859c7b40191bcdf63d48d9342bd22498549ee3a1dbae3302d928ad0cd0e2d23696a8bce0c53b7eda63b5167480a0003941935b909ee6dff97d6447ea48052db6f5fcd7668cee86b48ed21b4e5d03a01f7aba7a9dcd95803491d49c5ae30f1965b5825c46ae907147e8db39ae377e11547875f18d0f67ff43dfc9b35f16e322f2a316e21570f725c4f4ac2900ddcedb86b8e3b2785ea1aaede1f1a5f95723b160c9822e98723796f9abddcd68958b19cf938cbd6d43e872eaed8b393567a60257d9ed482f2892e49937a9bbc1e0350a6b1a5c7f6d8ee344a1eb303a9f9cc5ec52125817f15de746a95b3c5f5f65680203f8c5de1969df7d277ab137de8bc6040d010e0eba8cdb64488ae3dd935485ac9ac26724a0169")

type token struct {
	msgs [][]byte
	keys []PublicKey
	sig  *TokenSignature
	rng  io.Reader
}

func newToken(rng io.Reader, k Keypair, msg []byte) *token {
	return &token{
		msgs: [][]byte{msg},
		keys: []PublicKey{k.Public()},
		sig:  (&TokenSignature{}).Sign(rng, k, msg),
		rng:  rng,
	}
}

func (t *token) append(k Keypair, msg []byte) *token {
	t.sig = t.sig.Sign(t.rng, k, msg)
	t.msgs = append(t.msgs, msg)
	t.keys = append(t.keys, k.Public())
	return t
}

func (t *token) verify() error {
	return t.sig.Verify(t.keys, t.msgs)
}

func TestThreeMessages(t *testing.T) {
	rustRng := bytes.NewReader(rustRngBytes)

	m1 := []byte("hello")
	k1 := GenerateKeypair(rustRng)
	t1 := newToken(rustRng, k1, m1)
	if err := t1.verify(); err != nil {
		t.Errorf("error verifying token 1: %s", err)
	}

	m2 := []byte("world")
	k2 := GenerateKeypair(rustRng)
	t1.append(k2, m2)
	if err := t1.verify(); err != nil {
		t.Errorf("error verifying token 2: %s", err)
	}

	m3 := []byte("!!!")
	k3 := GenerateKeypair(rustRng)
	t1.append(k3, m3)
	if err := t1.verify(); err != nil {
		t.Errorf("error verifying token 3: %s", err)
	}

	rustz, _ := hex.DecodeString("89c2faac3ce9cf8a2fddf00eed56c2d821199e468f8a2eb70b10e817d59fb90e")
	rustp1, _ := hex.DecodeString("e8f71cf717e0b5c2e235b476ef7a9ecde77fcd5cc79585eca33c6fc1cedb3203")
	rustp2, _ := hex.DecodeString("6ada8cf321c26f3468b86f3ec0d4e5b16c54ae7f77a307f54725a9fc0d35e507")
	rustp3, _ := hex.DecodeString("fa0a82e1be2e8bf780d54967a4f65db583e6de1005e4bae2099235b9ca091f6c")
	rustParams := [][]byte{rustp1, rustp2, rustp3}
	if z := t1.sig.Z.Encode(nil); !bytes.Equal(z, rustz) {
		t.Errorf("wrong z: got %x, want %x", z, rustz)
	}
	for i, param := range t1.sig.Params {
		if p := param.Encode(nil); !bytes.Equal(p, rustParams[i]) {
			t.Errorf("wrong param[%d]: got %x, want %x", i, p, rustParams[i])
		}
	}
}

func TestChangeMessage(t *testing.T) {
	rustRng := bytes.NewReader(rustRngBytes)

	m1 := []byte("hello")
	k1 := GenerateKeypair(rustRng)
	t1 := newToken(rustRng, k1, m1)
	if err := t1.verify(); err != nil {
		t.Errorf("error verifying token 1: %s", err)
	}

	m2 := []byte("world")
	k2 := GenerateKeypair(rustRng)
	t1.append(k2, m2)
	t1.msgs[1] = []byte("you")

	if t1.verify() != ErrInvalidSignature {
		t.Error("token should not verify")
	}

	m3 := []byte("!!!")
	k3 := GenerateKeypair(rustRng)
	t1.append(k3, m3)
	if t1.verify() != ErrInvalidSignature {
		t.Error("token should not verify")
	}
}

func TestTokenSignatureEncodeDecode(t *testing.T) {
	rng := rand.Reader
	keypair := GenerateKeypair(rng)

	ts := &TokenSignature{}
	ts.Sign(rng, keypair, []byte("message"))

	params, z := ts.Encode()

	decodedTs, err := Decode(params, z)
	require.NoError(t, err)

	err = decodedTs.Verify([]PublicKey{keypair.Public()}, [][]byte{[]byte("message")})
	require.NoError(t, err)
}

func TestTokenSignatureDecodeErrors(t *testing.T) {
	tooShort := make([]byte, 31)
	tooLong := make([]byte, 33)

	testCases := []struct {
		Desc        string
		Params      [][]byte
		Z           []byte
		ExpectedErr error
	}{
		{
			Desc:        "Z too short",
			Z:           tooShort,
			ExpectedErr: ErrInvalidZSize,
		},
		{
			Desc:        "Z too big",
			Z:           tooLong,
			ExpectedErr: ErrInvalidZSize,
		},
		{
			Desc:   "Param too short",
			Params: [][]byte{tooShort},
		},
		{
			Desc:   "Param too long",
			Params: [][]byte{tooLong},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			_, err := Decode(testCase.Params, testCase.Z)
			require.Error(t, err)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			}
		})
	}
}

func TestTokenSignatureVerifyErrors(t *testing.T) {
	rng := rand.Reader

	t.Run("pubkey / msg count mismatch", func(t *testing.T) {
		ts := &TokenSignature{}
		require.Error(t, ts.Verify([]PublicKey{GenerateKeypair(rng).Public()}, [][]byte{[]byte("message1"), []byte("message2")}))
	})

	t.Run("params / msg count mismatch", func(t *testing.T) {
		ts := &TokenSignature{}
		kp1 := GenerateKeypair(rng)
		msg1 := []byte("message1")
		ts.Sign(rng, kp1, msg1)
		require.Error(t, ts.Verify(
			[]PublicKey{kp1.Public(), GenerateKeypair(rng).Public()},
			[][]byte{msg1, []byte("message2")},
		))
	})

	t.Run("no Z", func(t *testing.T) {
		ts := &TokenSignature{}
		kp1 := GenerateKeypair(rng)
		msg1 := []byte("message1")
		ts.Sign(rng, kp1, msg1)
		ts.Z = nil
		require.Error(t, ts.Verify(
			[]PublicKey{kp1.Public()},
			[][]byte{msg1},
		))
	})
}

func BenchmarkSign(b *testing.B) {
	k := GenerateKeypair(nil)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		(&TokenSignature{}).Sign(nil, k, []byte("hello"))
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, n := range []int{1, 2, 3, 5, 10} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			t := newToken(nil, GenerateKeypair(nil), []byte("hello"))
			for i := 1; i < n; i++ {
				t.append(GenerateKeypair(nil), []byte("foo"))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t.verify()
			}
		})
	}
}
