package biscuittest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/stretchr/testify/require"
)

type Samples struct {
	RootPrivateKey string     `json:"root_private_key"`
	RootPublicKey  string     `json:"root_public_key"`
	TestCases      []TestCase `json:"testcases"`
}

type TestCase struct {
	Title       string                `json:"title"`
	Filename    string                `json:"filename"`
	Token       []Block               `json:"token"`
	Validations map[string]Validation `json:"validations"`
}

type Block struct {
	Symbols     []string `json:"symbols"`
	PublicKeys  []any    `json:"public_keys"`
	ExternalKey any      `json:"external_key"`
	Code        string   `json:"code"`
}

type Result struct {
	Ok  *int `json:"Ok"`
	Err struct {
		FailedLogic struct {
			Unauthorized struct {
				Policy struct {
					Allow int `json:"Allow"`
				} `json:"policy"`
				Checks []struct {
					Block struct {
						BlockID int    `json:"block_id"`
						CheckID int    `json:"check_id"`
						Rule    string `json:"rule"`
					} `json:"Block"`
				} `json:"checks"`
			} `json:"Unauthorized"`
		} `json:"FailedLogic"`
	} `json:"Err"`
}

type Validation struct {
	World struct {
		Facts    []string `json:"facts"`
		Rules    []any    `json:"rules"`
		Checks   []string `json:"checks"`
		Policies []string `json:"policies"`
	} `json:"world"`
	Result         Result   `json:"result"`
	AuthorizerCode string   `json:"authorizer_code"`
	RevocationIds  []string `json:"revocation_ids"`
}

func CheckSample(c TestCase, t *testing.T) {
	fmt.Printf("Checking sample %s\n", c.Filename)
	b, err := os.ReadFile("./data/current/" + c.Filename)
	require.NoError(t, err)
	token, err := biscuit.Unmarshal(b)

	if err == nil {
		fmt.Printf("  Parsed file %s\n", c.Filename)
		// this sample uses a tampered biscuit file on purpose
		if c.Filename != "test006_reordered_blocks.bc" {
			CompareBlocks(*token, c.Token, t)
		}

	} else {
		fmt.Println("  Parsing failed, all validations must be errors")
		for _, v := range c.Validations {
			require.Nil(t, v.Result.Ok)
		}
	}
}

func CompareBlocks(token biscuit.Biscuit, blocks []Block, t *testing.T) {
	sample := token.Code()
	p := parser.New()

	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	authority, err := p.Block(blocks[0].Code)
	require.NoError(t, err)
	builder := biscuit.NewBuilder(privateRoot)
	builder.AddBlock(authority)
	r, err := builder.Build()
	require.NoError(t, err)
	rebuilt := *r

	for _, b := range blocks[1:] {
		parsed, err := p.Block(b.Code)
		require.NoError(t, err)
		builder := rebuilt.CreateBlock()
		builder.AddBlock(parsed)
		r, err := rebuilt.Append(rng, builder.Build())
		require.NoError(t, err)
		rebuilt = *r
	}

	require.Equal(t, sample, rebuilt.Code())
}

func CompareErrors(v Validation, t *testing.T) {

}

func TestReadSamples(t *testing.T) {
	b, err := os.ReadFile("./data/current/samples.json")
	require.NoError(t, err)
	var samples Samples
	err = json.Unmarshal(b, &samples)

	if err == nil {
		fmt.Printf("Checking %d samples\n", len(samples.TestCases))
		for _, v := range samples.TestCases {
			if v.Filename == "test017_expressions.bc" ||
				v.Filename == "test024_third_party.bc" ||
				v.Filename == "test025_check_all.bc" ||
				v.Filename == "test026_public_keys_interning.bc" {
				fmt.Printf("Skipping sample %s\n", v.Filename)
				continue
			}
			t.Run(v.Filename, func(t *testing.T) { CheckSample(v, t) })
		}

	} else {
		require.Fail(t, "parsing test cases failed")
	}
}
