package parser

import (
	"encoding/hex"
	"strings"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
)

type Rule struct {
	Head        *Predicate    `"*" @@ "<" "-"`
	Body        []*Predicate  `@@ ("," @@)*`
	Constraints []*Constraint `("@" @@ ("," @@)*)*`
}

type Predicate struct {
	Name string  `@Ident`
	IDs  []*Atom `"(" (@@ ("," @@)*)* ")"`
}

type Caveat struct {
	Queries []*Rule `"[" @@ ("|" "|" @@)* "]"`
}

type Atom struct {
	Symbol   *string    `"#" @Ident`
	Variable *uint32    `| "$" @Int`
	Bytes    *HexString `| @@`
	String   *string    `| @String`
	Integer  *int64     `| @Int`
}

type Constraint struct {
	VariableConstraint *VariableConstraint `@@`
	FunctionConstraint *FunctionConstraint `| @@`
}

type VariableConstraint struct {
	Variable *uint32           `"$" @Int`
	Date     *DateComparison   `((@@`
	Bytes    *BytesComparison  `| @@`
	String   *StringComparison `| @@`
	Int      *IntComparison    `| @@)`
	Set      *Set              `| @@)`
}

type FunctionConstraint struct {
	Function *string `@( "prefix" | "suffix" | "match" ) "("`
	Variable *uint32 `"$" @Int ","`
	Argument *string `@String ")"`
}

type IntComparison struct {
	Operation *string `@( (("="|">"|"<") "=") | "<" | ">" )`
	Target    *int64  `@Int`
}

type StringComparison struct {
	Operation *string `@("=" "=")`
	Target    *string `@String`
}

type BytesComparison struct {
	Operation *string    `@("=" "=")`
	Target    *HexString `@@`
}

type DateComparison struct {
	Operation *string `@("<" | ">")`
	Target    *string `@String`
}

type Set struct {
	Not     bool        `@"not"? "in"`
	Symbols []string    `("[" ("#" @Ident ("," "#" @Ident)*)+ "]"`
	Bytes   []HexString `| "[" ( @@ ("," @@)*)+ "]"`
	String  []string    `| "[" (@String ("," @String)*)+ "]"`
	Int     []int64     `| "[" (@Int ("," @Int)*)+ "]")`
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token, err := lex.Peek(0)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(token.Value, "hex:") {
		return participle.NextMatch
	}

	_, err = lex.Next()
	if err != nil {
		return err
	}

	*h = HexString(strings.TrimPrefix(token.Value, "hex:"))

	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}
