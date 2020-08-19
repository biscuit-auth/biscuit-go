// Package sig implements token signing and verification for Biscuit.
package sig

// Based on https://github.com/CleverCloud/biscuit-rust/blob/master/src/crypto/mod.rs

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	r255 "github.com/gtank/ristretto255"
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

// TokenSignature holds a signature across one or more token messages.
type TokenSignature struct {
	Params []*r255.Element
	Z      *r255.Scalar
}

// Sign adds a signature to s across msg using k and returns s. If rng is nil, a
// safe CSPRNG is used. It is safe to call Sign against a zero TokenSignature.
func (s *TokenSignature) Sign(rng io.Reader, k Keypair, msg []byte) *TokenSignature {
	r := randomScalar(rng)
	A := (&r255.Element{}).ScalarBaseMult(r)
	d := hashPoint(A)
	e := hashMessage(k.public.e, msg)
	z := &r255.Scalar{}
	z = z.Multiply(r, d).Subtract(z, e.Multiply(e, k.Private().s))
	s.Params = append(s.Params, A)
	if s.Z == nil {
		s.Z = z
	} else {
		s.Z = s.Z.Add(s.Z, z)
	}
	return s
}

// ErrInvalidSignature indicates that signature verification failed.
var ErrInvalidSignature = errors.New("sig: invalid signature")

var ristrettoIdentity = r255.NewElement()

// Verify verifies the signature against a list of public keys and messages. The
// number of signature parameters, pubkeys, and msgs must be the same. Returns
// nil if the signature is valid and ErrInvalidSignature if invalid.
func (s *TokenSignature) Verify(pubkeys []PublicKey, msgs [][]byte) error {
	if len(pubkeys) != len(msgs) {
		return errors.New("sig: wrong number of keys or messages")
	}
	if len(msgs) != len(s.Params) {
		return errors.New("sig: wrong number of params or messages")
	}
	if s.Z == nil {
		return errors.New("sig: missing Z")
	}

	zP := (&r255.Element{}).ScalarBaseMult(s.Z)

	pubs := make([]*r255.Element, len(pubkeys))
	hashes := make([]*r255.Scalar, len(msgs))
	for i, k := range pubkeys {
		pubs[i] = k.e
		hashes[i] = hashMessage(k.e, msgs[i])
	}
	eiXi := r255.NewElement().MultiScalarMult(hashes, pubs)

	for i, A := range s.Params {
		hashes[i] = hashPoint(A)
	}
	diAi := r255.NewElement().MultiScalarMult(hashes, s.Params)

	res := zP.Add(zP, eiXi).Subtract(zP, diAi)
	if ristrettoIdentity.Equal(res) != 1 {
		return ErrInvalidSignature
	}
	return nil
}

func (s *TokenSignature) Encode() ([][]byte, []byte) {
	params := make([][]byte, len(s.Params))
	for i, p := range s.Params {
		params[i] = p.Encode([]byte{})
	}

	return params, s.Z.Encode([]byte{})
}

func Decode(params [][]byte, z []byte) (*TokenSignature, error) {
	decodedParams := make([]*r255.Element, len(params))
	for i, p := range params {
		e := &r255.Element{}
		if err := e.Decode(p); err != nil {
			return nil, err
		}
		decodedParams[i] = e
	}

	decodedZ := &r255.Scalar{}
	if err := decodedZ.Decode(z); err != nil {
		return nil, err
	}

	return &TokenSignature{
		Params: decodedParams,
		Z:      decodedZ,
	}, nil
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
