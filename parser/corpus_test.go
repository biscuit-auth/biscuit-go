// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite "+corpusGolden)

const (
	corpusSamples = "../samples/data/current/samples.json"
	corpusGolden  = "testdata/samples_corpus.golden"
)

// Parses every datalog snippet in the spec samples and compares the outcome
// (accepted, with this AST, or rejected) with the checked-in golden file, so
// a grammar or lexer change that alters any outcome shows up as a diff.
//
// Regenerate with: go test ./parser/ -run TestSamplesCorpus -update
func TestSamplesCorpus(t *testing.T) {
	raw, err := os.ReadFile(corpusSamples)
	require.NoError(t, err)

	var samples struct {
		TestCases []struct {
			Filename string `json:"filename"`
			Token    []struct {
				Code string `json:"code"`
			} `json:"token"`
			Validations map[string]struct {
				AuthorizerCode string `json:"authorizer_code"`
			} `json:"validations"`
		} `json:"testcases"`
	}
	require.NoError(t, json.Unmarshal(raw, &samples))

	p := New()
	var lines []string
	for _, tc := range samples.TestCases {
		for i, b := range tc.Token {
			parsed, err := p.Block(b.Code, nil)
			lines = append(lines, corpusLine(fmt.Sprintf("%s block %d", tc.Filename, i), parsed, err))
		}

		names := make([]string, 0, len(tc.Validations))
		for n := range tc.Validations {
			names = append(names, n)
		}
		sort.Strings(names)
		for i, n := range names {
			parsed, err := p.Authorizer(tc.Validations[n].AuthorizerCode, nil)
			lines = append(lines, corpusLine(fmt.Sprintf("%s authorizer %d", tc.Filename, i), parsed, err))
		}
	}
	got := strings.Join(lines, "\n") + "\n"

	if *update {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(corpusGolden, []byte(got), 0o644))
		return
	}

	want, err := os.ReadFile(corpusGolden)
	require.NoError(t, err, "missing golden file; run with -update to create it")
	require.Equal(t, string(want), got, "parser outcome changed; review the diff and run with -update if intended")
}

func corpusLine(key string, parsed interface{}, err error) string {
	if err != nil {
		return key + "\terror"
	}
	return key + "\tok\t" + strconv.Quote(fmt.Sprintf("%+v", parsed))
}
