// Package sig implements token signing and verification for Biscuit.
package sig

// Based on https://github.com/CleverCloud/biscuit-rust/blob/master/src/crypto/mod.rs
/*
import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/ed25519"
	"errors"
	"io"
)

// GenerateKeypair generates a new keypair. If rng is nil, a safe CSPRNG is
// used.
func GenerateKeypair(rng io.Reader) Keypair {
	return NewKeypair(PrivateKey{s: randomScalar(rng)})
}

// NewKeypair returns a new keypair based on the provided private key.
func NewKeypair(k PrivateKey) Keypair {
	return Keypair{
		private: k,
		public:  PublicKey{e: (&r255.Element{}).ScalarBaseMult(k.s)},
	}
}

// Keypair holds a private and public key used to sign tokens.
type Keypair struct {
	private PrivateKey
	public  PublicKey
}

// Private returns the private key.
func (k Keypair) Private() PrivateKey {
	return k.private
}

// Public returns the public key.
func (k Keypair) Public() PublicKey {
	return k.public
}

// NewPrivateKey returns a PrivateKey built from a 32-byte compressed private
// key (the output of Bytes).
func NewPrivateKey(k []byte) (PrivateKey, error) {
	pk := PrivateKey{s: &r255.Scalar{}}
	return pk, pk.s.Decode(k)
}

// PrivateKey holds a private key.
type PrivateKey struct {
	s *r255.Scalar
}

// Bytes returns the 32-byte compressed private key.
func (k PrivateKey) Bytes() []byte {
	return k.s.Encode(nil)
}

// NewPublicKey returns a PublicKey built from a 32-byte compressed public key
// (the output of Bytes).
func NewPublicKey(k []byte) (PublicKey, error) {
	pk := PublicKey{e: &r255.Element{}}
	return pk, pk.e.Decode(k)
}

// PublicKey holds a public key.
type PublicKey struct {
	e *r255.Element
}

// Bytes returns the 32-byte compressed public key.
func (k PublicKey) Bytes() []byte {
	return k.e.Encode(nil)
}

func randomScalar(rng io.Reader) *r255.Scalar {
	var k [64]byte
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, k[:]); err != nil {
		panic(err)
	}
	return (&r255.Scalar{}).FromUniformBytes(k[:])
}

func hashPoint(p *r255.Element) *r255.Scalar {
	h := sha512.New()
	buf := make([]byte, 0, sha512.Size)
	h.Write(p.Encode(buf[:0]))
	return (&r255.Scalar{}).FromUniformBytes(h.Sum(buf[:0]))
}

func hashMessage(point *r255.Element, data []byte) *r255.Scalar {
	h := sha512.New()
	buf := make([]byte, 0, sha512.Size)
	h.Write(point.Encode(buf))
	h.Write(data)
	return (&r255.Scalar{}).FromUniformBytes(h.Sum(buf[:0]))
}
*/