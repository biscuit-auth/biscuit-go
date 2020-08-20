package parser

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
	Symbol   *string `"#" @Ident`
	Variable *uint32 `| "$" @Int`
	String   *string `| @String`
	Integer  *int64  `| @Int`
}

type Constraint struct {
	VariableConstraint *VariableConstraint `@@`
	FunctionConstraint *FunctionConstraint `| @@`
}

type VariableConstraint struct {
	Variable *uint32           `"$" @Int`
	Date     *DateComparison   `((@@`
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

type DateComparison struct {
	Operation *string `@("<" | ">")`
	Target    *string `@(String)`
}

type Set struct {
	Not     bool     `@"not"? "in"`
	Symbols []string `("[" ("#" @Ident ("," "#" @Ident)*)+ "]"`
	String  []string `| "[" (@String ("," @String)*)+ "]"`
	Int     []int64  `| "[" (@Int ("," @Int)*)+ "]")`
}
