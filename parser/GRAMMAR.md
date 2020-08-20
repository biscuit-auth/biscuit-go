# Parser Grammar

This document describes the currently supported datalog grammar

## Atom

Represent a datalog type, can be one of: symbol, variable, integer, string and date

- symbol are prefixed by a `#` sign followed by a string, e.g. `#read`
- variable are prefixed by a `$` sign followed by an unsigned 32bit integer,  e.g. `$0`
- integer are any int64
- string are any utf8 characters sequence, between double quotes, e.g. `"/path/to/file.txt"`
- date are RFC3339 encoded dates, e.g. `2006-01-02T15:04:05Z07:00`

## Predicate

A predicate is a list of atoms, grouped under a name in the form `Name(Atom0, Atom1, ..., AtomN)` , e.g. `parent(#a, #b)`

## Constraints

Constraints allows to perform checks on a variable, below is the list of available operations by type and their expected format.

### Integer:

- Equal: `0? == 1`
- Greater: `0? > 1`
- Greater or equal: `0? >= 1`
- Lesser: `0? < 1`
- Lesser or equal: `0? <= 1`
- In: `0? in [1, 2, 3]`
- Not in: `0? not in [1, 2, 3]`

###  String

- Equal: `0? == "abc"`
- Start with: `prefix(0?, "abc")`
- End with: `suffix(0?, "abc")`
- Regexp: `match(0?, "^abc\s+def$") `
- In: `0? in ["abc", "def"]`
- Not in: `0? not in ["abc", "def"]`

### Date

- Before: `0? < "2006-01-02T15:04:05Z07:00"`
- After: `0? > "2006-01-02T15:04:05Z07:00"`

### Symbols

- In:`0? in [#a, #b, #c]`
- Not in:`0? not in [#a, #b, #c]`

## Fact

A fact is a single predicate that does not contains any variable, e.g. `right(#authority, "file1.txt", #read)`

# Rule

A rule is formed from a head, a body and a list of constraints.
The head is a single predicate, the body a list of predicates, and followed by an optional list of constraints.

It has the following format: `*Head <- Body @ Conditions`

e.g. `*right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1) @ $0 == "username", prefix($1, "/home/username")`

# Caveat

A caveat is list of rules following the format: `[ rule0 || rule1 || ... || ruleN ]`
