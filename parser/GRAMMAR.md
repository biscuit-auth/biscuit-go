# Parser Grammar

This document describes the currently supported Datalog grammar.

## Term

Represents a Datalog type, can be one of: parameter, variable, integer, string, date, bytes, boolean, null, set, array, or map.

- parameter is delimited by curly brackets: `{param}`. Those are replaced by actual values before evaluation.
- variable is prefixed with a `$` sign followed by a string or an unsigned 32bit base-10 integer,  e.g. `$0` or `$variable1`
- integer is any base-10 int64
- string is any utf8 character sequence, between double quotes, e.g. `"/path/to/file.txt"`
- date is RFC3339 encoded, e.g. `2006-01-02T15:04:05Z`
- bytes is an hexadecimal encoded string, prefixed with a `hex:` sequence
- boolean is either `true` or `false`
- null is the absence of a value, written `null` (datalog v3.3); `$x == null` tests for it
- set is a sequence of any of the above types, except variable, between braces, e.g. `{"file1", "file2"}`; the empty set is `{,}` (sets cannot be nested)
- array is an ordered sequence of terms of any type, except variable, between brackets, e.g. `[1, "a", [2]]` (datalog v3.3); the empty array is `[]`
- map associates integer or string keys with terms of any type, except variable, e.g. `{"a": 1, 2: "b"}` (datalog v3.3); the empty map is `{}`

## Predicate

A predicate is a list of terms, grouped under a name in the form `Name(Term0, Term1, ..., TermN)` , e.g. `parent("a", "b")`.

## Constraints

Constraints allows performing checks on a variable, below is the list of available operations by type and their expected format.

### Boolean

- Equal: `$b == true`
- Negation: `!$b`
- And / Or: `$b || $c && $d`. The right side is evaluated only when needed (datalog v3.3).

### Integer

Integer literals are signed 64-bit; an operation that overflows is an execution error.

- Equal: `$i === 1`
- Not equal: `$i !== 1`
- Bitwise and / or / xor: `$i & 1`, `$i | 1`, `$i ^ 1`
- Greater than: `$i > 1`
- Greater than or equal: `$i >= 1`
- Less than: `$i < 1`
- Less than or equal: `$i <= 1`
- Arithmetic (`*`, `/`, `+`, `-`)

###  String

- Equal: `$s == "abc"`
- Starts with: `$s.starts_with("abc")`
- Ends with: `$s.ends_with("abc")`
- Regular expression: `$s.matches("^abc\s+def$") `
- Contains: `$s.contains("abc")`
- Length: `$s.length()`

### Date

- Equal: `$date == "2006-01-02T15:04:05Z07:00"`
- Before (strict): `$date < "2006-01-02T15:04:05Z07:00"`
- Before: `$date <= "2006-01-02T15:04:05Z07:00"`
- After (strict): `$date > "2006-01-02T15:04:05Z07:00"`
- Before: `$date <= "2006-01-02T15:04:05Z07:00"`

### Bytes

- Equal: `$b == "hex:3df97fb5"`
- Length: `$b.length()`

### Set

- Equal: `$set === {"a", "b"}`
- Contains (element membership): `$set.contains("a")`
- Contains (set inclusion): `$set.contains({"a"})`
- Union: `$set.union({"a"})`
- Intersection: `$set.intersection({"a"})`
- Length: `$set.length()`
- All / Any (datalog v3.3): `$set.all($p -> $p > 0)`, `$set.any($p -> $p > 2)`. The closure parameter
  may not have the name of a variable already bound in the rule.

### Array (datalog v3.3)

- Equal: `$array == [1, 2]`
- Contains: `$array.contains(1)`
- Prefix / Suffix: `$array.starts_with([1])`, `$array.ends_with([2])`
- Get: `$array.get(0)`, `null` when the index is out of range
- Length, All, Any: as for sets

### Map (datalog v3.3)

- Equal: `$map == {"a": 1}`
- Contains (key membership): `$map.contains("a")`
- Get: `$map.get("a")`, `null` when the key is absent
- Length: `$map.length()`
- All / Any: the closure receives each entry as a `[key, value]` array, e.g. `$map.all($kv -> $kv.get(1) > 0)`

### Any value (datalog v3.3)

- Type name: `$x.type()` returns one of `"integer"`, `"string"`, `"date"`, `"bytes"`, `"bool"`,
  `"set"`, `"null"`, `"array"` or `"map"`, e.g. `$x.type() == "integer"`
- Extern function call: `$x.extern::name()` or `$x.extern::name($y)`, where `name` is a function
  registered on the authorizer with `biscuit.WithExternFuncs`. A call to a name that is not
  registered fails the evaluation.

### Operators precedence

The operators have the following precedence (highest to lowest):


| Operators                   | Associativity    |
|-----------------------------|------------------|
| `!` (prefix)                | not associative  |
| `*`, `/`                    | left-associative |
| `+`, `-`                    | left-associative |
| `&`                         | left-associative |
| `|`                         | left-associative |
| `^`                         | left-associative |
| `>`, `>=`, `<`, `<=`, `===`, `==`, `!==`, `!=` | not associative |

`===` and `!==` are the strict comparisons: comparing values of different types is an error.
`==` and `!=` compare across types (datalog v3.3): values of different types are not equal.
| `&&`                        | left-associative |
| `||`                        | left-associative |

Parentheses can be used to force precedence (or to make it explicit).


## Fact

A fact is a single predicate that does not contain any variables, e.g. `right("file1.txt", "read")`.

# Rule

A rule is formed from a head, a body, and a list of constraints.
The head is a single predicate, the body is a list of predicates or constraints. Variables present in the head and in constraints must be introduced by predicates in the body.

It has the format: `Head <- (predicate, constraint)+`.

e.g. `right($file, "read") <- resource($file), owner($user, $file), $user == "username", $file.starts_with("/home/username")`

# Check

A check starts with `check if`, `check all` or `reject if`, followed by one or more rule bodies,
separated with ` or `.

`check if` passes when one of the bodies has at least one match. `check all` passes when one of the
bodies has at least one match and every match of that body satisfies its expressions, e.g.
`check all operation($op), allowed_operations($allowed), $allowed.contains($op)`. `reject if`
passes when none of the bodies has a match.

# Policy

A policy starts with either `allow if` or `deny if`, followed by one or more rule bodies, separated with ` or `.

# Scope

A rule body, a check body or a policy body may end with a `trusting` clause that selects which
blocks of the token it reads facts from: `trusting authority`, `trusting previous` (every block up
to the current one) or `trusting <public key>` (the third-party blocks signed by that key, written
`ed25519/<hex>` or `secp256r1/<hex>`). Entries are separated with commas, e.g.
`check if group("admin") trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189`.

Without a clause, a body reads the authority block, the authorizer and its own block. A block or an
authorizer may set the default for all its bodies with a `trusting ...;` statement.
