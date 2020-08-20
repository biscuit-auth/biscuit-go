# Parser Grammar

This document describes the currently supported Datalog grammar.

## Atom

Represents a Datalog type, can be one of: symbol, variable, integer, string, or date.

- symbol is prefixed with a `#` sign followed by text, e.g. `#read`
- variable is prefixed with a `$` sign followed by an unsigned 32bit base-10 integer,  e.g. `$0`
- integer is any base-10 int64
- string is any utf8 character sequence, between double quotes, e.g. `"/path/to/file.txt"`
- date is RFC3339 encoded, e.g. `2006-01-02T15:04:05Z07:00`

## Predicate

A predicate is a list of atoms, grouped under a name in the form `Name(Atom0, Atom1, ..., AtomN)` , e.g. `parent(#a, #b)`.

## Constraints

Constraints allows performing checks on a variable, below is the list of available operations by type and their expected format.

### Integer:

- Equal: `0? == 1`
- Greater than: `0? > 1`
- Greater than or equal: `0? >= 1`
- Less than: `0? < 1`
- Less than or equal: `0? <= 1`
- In: `0? in [1, 2, 3]`
- Not in: `0? not in [1, 2, 3]`

###  String

- Equal: `0? == "abc"`
- Starts with: `prefix(0?, "abc")`
- Ends with: `suffix(0?, "abc")`
- Regular expression: `match(0?, "^abc\s+def$") `
- In: `0? in ["abc", "def"]`
- Not in: `0? not in ["abc", "def"]`

### Date

- Before: `0? < "2006-01-02T15:04:05Z07:00"`
- After: `0? > "2006-01-02T15:04:05Z07:00"`

### Symbols

- In:`0? in [#a, #b, #c]`
- Not in:`0? not in [#a, #b, #c]`

## Fact

A fact is a single predicate that does not contain any variables, e.g. `right(#authority, "file1.txt", #read)`.

# Rule

A rule is formed from a head, a body, and a list of constraints.
The head is a single predicate, the body is a list of predicates, and followed by an optional list of constraints.

It has the format: `*Head <- Body @ Conditions`

e.g. `*right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1) @ $0 == "username", prefix($1, "/home/username")`

# Caveat

A caveat is list of rules with the format: `[ rule0 || rule1 || ... || ruleN ]`
