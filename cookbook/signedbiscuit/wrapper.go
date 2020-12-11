package signedbiscuit

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
)

var (
	ErrAlreadySigned           = errors.New("already signed")
	ErrInvalidToSignDataPrefix = errors.New("invalid to_sign data prefix")
)

var (
	signStaticCtx = []byte("biscuit-pop-v0")
	challengeSize = 16
	nonceSize     = 16
)

type signedBiscuitBuilder struct {
	biscuit.Builder
}

// withUserToSignFact add an authority should_sign fact and associated data to the biscuit
// with an authority caveat requiring the verifier to provide a valid_signature fact.
// the verifier is responsible of ensuring that a valid signature exists over the data.
func (b *signedBiscuitBuilder) withUserToSignFact(userPubkey []byte) error {
	dataID := biscuit.Integer(0)

	if err := validatePKIXP256PublicKey(userPubkey); err != nil {
		return err
	}

	if err := b.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "should_sign",
		IDs: []biscuit.Atom{
			dataID,
			biscuit.Symbol(ECDSA_P256_SHA256),
			biscuit.Bytes(userPubkey),
		},
	}}); err != nil {
		return err
	}

	challenge := make([]byte, challengeSize)
	if _, err := rand.Reader.Read(challenge); err != nil {
		return err
	}

	if err := b.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "data",
		IDs: []biscuit.Atom{
			dataID,
			biscuit.Bytes(append(signStaticCtx, challenge...)),
		},
	}}); err != nil {
		return err
	}

	if err := b.AddAuthorityCaveat(biscuit.Caveat{Queries: []biscuit.Rule{{
		Head: biscuit.Predicate{Name: "valid", IDs: []biscuit.Atom{biscuit.Variable("dataID")}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Variable("dataID"),
				biscuit.Variable("alg"),
				biscuit.Variable("pubkey"),
			}},
			{Name: "valid_signature", IDs: []biscuit.Atom{
				biscuit.Symbol("ambient"),
				biscuit.Variable("dataID"),
				biscuit.Variable("alg"),
				biscuit.Variable("pubkey"),
			}},
		},
	}}}); err != nil {
		return err
	}

	return nil
}

// withAudienceSignature add an authority audience_signature fact, containing a challenge and
// a matching signature using the audience key.
// the verifier is responsible of providing a valid_audience_signature fact, after
// verifying the signature using the audience pubkey.
func (b *signedBiscuitBuilder) withAudienceSignature(audience string, audienceKey crypto.Signer) error {
	if len(audience) == 0 {
		return errors.New("audience is required")
	}

	data, err := audienceSign(audience, audienceKey)
	if err != nil {
		return err
	}

	if err := b.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "audience_signature",
		IDs: []biscuit.Atom{
			data.Audience,
			data.Challenge,
			data.Signature,
		},
	}}); err != nil {
		return err
	}

	if err := b.AddAuthorityCaveat(biscuit.Caveat{Queries: []biscuit.Rule{{
		Head: biscuit.Predicate{Name: "valid_audience", IDs: []biscuit.Atom{biscuit.Variable("audience")}},
		Body: []biscuit.Predicate{
			{Name: "audience_signature", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Variable("audience"),
				biscuit.Variable("challenge"),
				biscuit.Variable("signature"),
			}},
			{Name: "valid_audience_signature", IDs: []biscuit.Atom{
				biscuit.Symbol("ambient"),
				biscuit.Variable("audience"),
				biscuit.Variable("signature"),
			}},
		},
	}}}); err != nil {
		return err
	}

	return nil
}

func (b *signedBiscuitBuilder) withMetadata(m *Metadata) error {

	userGroups := make(biscuit.Set, 0, len(m.UserGroups))
	for _, g := range m.UserGroups {
		userGroups = append(userGroups, biscuit.String(g))
	}

	return b.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "metadata",
		IDs: []biscuit.Atom{
			biscuit.String(m.ClientID),
			biscuit.String(m.UserID),
			biscuit.String(m.UserEmail),
			userGroups,
			biscuit.Date(m.IssueTime),
		},
	}})
}

func (b *signedBiscuitBuilder) withExpire(exp time.Time) error {
	if err := b.AddAuthorityCaveat(biscuit.Caveat{Queries: []biscuit.Rule{{
		Head: biscuit.Predicate{Name: "not_expired", IDs: []biscuit.Atom{biscuit.Variable("now")}},
		Body: []biscuit.Predicate{
			{Name: "current_time", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable("now")}},
		},
		Constraints: []biscuit.Constraint{{
			Name: biscuit.Variable("now"),
			Checker: biscuit.DateComparisonChecker{
				Comparison: datalog.DateComparisonBefore,
				Date:       biscuit.Date(exp),
			},
		}},
	}}}); err != nil {
		return err
	}

	return nil
}

type signedBiscuitBlockBuilder struct {
	biscuit.BlockBuilder
}

func (b *signedBiscuitBlockBuilder) withUserSignature(sigData *userSignatureData) error {
	return b.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "signature",
		IDs: []biscuit.Atom{
			sigData.DataID,
			sigData.UserPubKey,
			sigData.Signature,
			sigData.Nonce,
			sigData.Timestamp,
		},
	}})
}

type signedBiscuitVerifier struct {
	biscuit.Verifier
}

func (v *signedBiscuitVerifier) getUserToSignData(userPubKey biscuit.Bytes) (*userToSignData, error) {
	toSign, err := v.Query(biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "to_sign",
			IDs:  []biscuit.Atom{biscuit.Variable("dataID"), biscuit.Variable("alg"), biscuit.Variable("pubkey")},
		},
		Body: []biscuit.Predicate{
			{
				Name: "should_sign", IDs: []biscuit.Atom{
					biscuit.SymbolAuthority,
					biscuit.Variable("dataID"),
					biscuit.Variable("alg"),
					biscuit.Bytes(userPubKey),
				},
			}, {
				Name: "data", IDs: []biscuit.Atom{
					biscuit.SymbolAuthority,
					biscuit.Variable("dataID"),
					biscuit.Variable("pubkey"),
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if g, w := len(toSign), 1; g != w {
		return nil, fmt.Errorf("invalid to_sign fact count, got %d, want %d", g, w)
	}

	toSignFact := toSign[0]
	if g, w := len(toSignFact.IDs), 3; g != w {
		return nil, fmt.Errorf("invalid to_sign fact, got %d atoms, want %d", g, w)
	}

	sigData := &userToSignData{}
	var ok bool
	sigData.DataID, ok = toSign[0].IDs[0].(biscuit.Integer)
	if !ok {
		return nil, errors.New("invalid to_sign atom: dataID")
	}
	sigData.Alg, ok = toSign[0].IDs[1].(biscuit.Symbol)
	if !ok {
		return nil, errors.New("invalid to_sign atom: alg")
	}
	sigData.Data, ok = toSign[0].IDs[2].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid to_sign atom: data")
	}

	if !bytes.HasPrefix(sigData.Data, signStaticCtx) {
		return nil, ErrInvalidToSignDataPrefix
	}

	return sigData, nil
}

func (v *signedBiscuitVerifier) ensureNotAlreadyUserSigned(dataID biscuit.Integer, userPubKey biscuit.Bytes) error {
	alreadySigned, err := v.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "already_signed", IDs: []biscuit.Atom{dataID, userPubKey, biscuit.Variable("signerTimestamp")}},
		Body: []biscuit.Predicate{
			{Name: "signature", IDs: []biscuit.Atom{
				dataID,
				userPubKey,
				biscuit.Variable("signature"),
				biscuit.Variable("signerNonce"),
				biscuit.Variable("signerTimestamp"),
			}},
		},
	})
	if err != nil {
		return err
	}
	if len(alreadySigned) != 0 {
		return ErrAlreadySigned
	}

	return nil
}

func (v *signedBiscuitVerifier) getUserVerificationData() (*userVerificationData, error) {
	toValidate, err := v.Query(biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "to_validate",
			IDs: []biscuit.Atom{
				biscuit.Variable("dataID"),
				biscuit.Variable("alg"),
				biscuit.Variable("pubkey"),
				biscuit.Variable("data"),
				biscuit.Variable("signature"),
				biscuit.Variable("signerNonce"),
				biscuit.Variable("signerTimestamp"),
			}},
		Body: []biscuit.Predicate{
			{Name: "should_sign", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Variable("dataID"),
				biscuit.Variable("alg"),
				biscuit.Variable("pubkey"),
			}},
			{Name: "data", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Variable("dataID"),
				biscuit.Variable("data"),
			}},
			{Name: "signature", IDs: []biscuit.Atom{
				biscuit.Variable("dataID"),
				biscuit.Variable("pubkey"),
				biscuit.Variable("signature"),
				biscuit.Variable("signerNonce"),
				biscuit.Variable("signerTimestamp"),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	if g, w := len(toValidate), 1; g != w {
		return nil, fmt.Errorf("invalid to_validate fact count, got %d, want %d", g, w)
	}

	toValidateFact := toValidate[0]
	if g, w := len(toValidateFact.IDs), 7; g != w {
		return nil, fmt.Errorf("invalid to_valid fact atom count, got %d, want %d", g, w)
	}

	toVerify := &userVerificationData{}
	var ok bool
	toVerify.DataID, ok = toValidateFact.IDs[0].(biscuit.Integer)
	if !ok {
		return nil, errors.New("invalid to_validate atom: dataID")
	}
	toVerify.Alg, ok = toValidateFact.IDs[1].(biscuit.Symbol)
	if !ok {
		return nil, errors.New("invalid to_validate atom: alg")
	}
	toVerify.UserPubKey, ok = toValidateFact.IDs[2].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid to_validate atom: userPubKey")
	}
	toVerify.Data, ok = toValidateFact.IDs[3].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid to_validate atom: data")
	}
	toVerify.Signature, ok = toValidateFact.IDs[4].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid to_validate atom: signature")
	}
	toVerify.Nonce, ok = toValidateFact.IDs[5].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid to_validate atom: nonce")
	}
	toVerify.Timestamp, ok = toValidateFact.IDs[6].(biscuit.Date)
	if !ok {
		return nil, errors.New("invalid to_validate atom: timestamp")
	}

	return toVerify, nil
}

func (v *signedBiscuitVerifier) withValidatedUserSignature(data *userVerificationData) error {
	v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "valid_signature",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), data.DataID, data.Alg, data.UserPubKey},
	}})

	return nil
}

func (v *signedBiscuitVerifier) getAudienceVerificationData(audience string) (*audienceVerificationData, error) {
	toValidate, err := v.Query(biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "audience_to_validate",
			IDs: []biscuit.Atom{
				biscuit.Variable("challenge"),
				biscuit.Variable("signature"),
			}},
		Body: []biscuit.Predicate{
			{Name: "audience_signature", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Symbol(audience),
				biscuit.Variable("challenge"),
				biscuit.Variable("signature"),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	if g, w := len(toValidate), 1; g != w {
		return nil, fmt.Errorf("invalid audience_to_validate fact count, got %d, want %d", g, w)
	}

	toValidateFact := toValidate[0]
	if g, w := len(toValidateFact.IDs), 2; g != w {
		return nil, fmt.Errorf("invalid audience_to_validate fact atom count, got %d, want %d", g, w)
	}

	toVerify := &audienceVerificationData{Audience: biscuit.Symbol(audience)}
	var ok bool
	toVerify.Challenge, ok = toValidateFact.IDs[0].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid audience_to_validate atom: challenge")
	}
	toVerify.Signature, ok = toValidateFact.IDs[1].(biscuit.Bytes)
	if !ok {
		return nil, errors.New("invalid audience_to_validate atom: signature")
	}

	return toVerify, nil
}

func (v *signedBiscuitVerifier) getMetadata() (*Metadata, error) {
	metaFacts, err := v.Query(biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "metadata",
			IDs: []biscuit.Atom{
				biscuit.Variable("clientID"),
				biscuit.Variable("userID"),
				biscuit.Variable("userEmail"),
				biscuit.Variable("userGroups"),
				biscuit.Variable("issueTime"),
			}},
		Body: []biscuit.Predicate{
			{Name: "metadata", IDs: []biscuit.Atom{
				biscuit.SymbolAuthority,
				biscuit.Variable("clientID"),
				biscuit.Variable("userID"),
				biscuit.Variable("userEmail"),
				biscuit.Variable("userGroups"),
				biscuit.Variable("issueTime"),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	if g, w := len(metaFacts), 1; g != w {
		return nil, fmt.Errorf("invalid metadata fact count, got %d, want %d", g, w)
	}

	metaFact := metaFacts[0]

	clientID, ok := metaFact.IDs[0].(biscuit.String)
	if !ok {
		return nil, errors.New("invalid metadata atom: clientID")
	}
	userID, ok := metaFact.IDs[1].(biscuit.String)
	if !ok {
		return nil, errors.New("invalid metadata atom: userID")
	}
	userEmail, ok := metaFact.IDs[2].(biscuit.String)
	if !ok {
		return nil, errors.New("invalid metadata atom: userEmail")
	}
	userGroups, ok := metaFact.IDs[3].(biscuit.Set)
	if !ok {
		return nil, errors.New("invalid metadata atom: userGroups")
	}
	issueTime, ok := metaFact.IDs[4].(biscuit.Date)
	if !ok {
		return nil, errors.New("invalid metadata atom: issueTime")
	}

	groups := make([]string, 0, len(userGroups))
	for _, g := range userGroups {
		grpStr, ok := g.(biscuit.String)
		if !ok {
			return nil, fmt.Errorf("invalid set atom: got %T, want biscuit.String", g)
		}
		groups = append(groups, string(grpStr))
	}

	return &Metadata{
		ClientID:   string(clientID),
		UserID:     string(userID),
		UserEmail:  string(userEmail),
		UserGroups: groups,
		IssueTime:  time.Time(issueTime),
	}, nil
}

func (v *signedBiscuitVerifier) withValidatedAudienceSignature(data *audienceVerificationData) error {
	v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "valid_audience_signature",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), data.Audience, data.Signature},
	}})

	return nil
}

func (v *signedBiscuitVerifier) withCurrentTime(t time.Time) error {
	v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "current_time",
		IDs: []biscuit.Atom{
			biscuit.Symbol("ambient"),
			biscuit.Date(t),
		},
	}})

	return nil
}
