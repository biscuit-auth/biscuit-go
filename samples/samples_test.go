package samples

import (
	"io/ioutil"
	"testing"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestSample1Basic(t *testing.T) {
	token, err := ioutil.ReadFile("test1_basic.bc")
	require.NoError(t, err)

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	s, err := b.Serialize()
	require.NoError(t, err)

	require.Equal(t, len(token), len(s))
}

func TestInvalidSignature(t *testing.T) {
	token, err := ioutil.ReadFile("test5_invalid_signature.bc")
	require.NoError(t, err)

	b, err := biscuit.Unmarshal(token)
	require.Equal(t, sig.ErrInvalidSignature, err)
	require.Nil(t, b)
}
