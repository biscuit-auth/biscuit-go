// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"
)

const (
	benchFact  = `right("/a/file1.txt", "read", {"read", "/a/file2.txt"})`
	benchRule  = `grandparent($a, $c) <- parent($a, $b), parent($b, $c), $a.starts_with("x") || $c == "y"`
	benchCheck = `check if resource($0), operation("read"), right($0, "read"), $0.length() < 100 or admin(true)`
	benchBlock = `// a block
right("/a/file1", "read");
right("/a/file1", "write");
right("/a/file2", "read");
grandparent($a, $c) <- parent($a, $b), parent($b, $c);
check if resource($0), operation("read"), right($0, "read");
check if time($t), $t < 2030-12-31T12:59:59+00:00;
`
	benchAuthorizer = `resource("/a/file1");
operation("read");
time(2025-01-01T00:00:00Z);
check if right($r, "read"), resource($r);
allow if user("alice") or user("bob");
deny if true;
`
)

func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		New()
	}
}

func BenchmarkParser(b *testing.B) {
	p := New()

	cases := []struct {
		name string
		fn   func() error
	}{
		{"fact", func() error { _, err := p.Fact(benchFact, nil); return err }},
		{"rule", func() error { _, err := p.Rule(benchRule, nil); return err }},
		{"check", func() error { _, err := p.Check(benchCheck, nil); return err }},
		{"block", func() error { _, err := p.Block(benchBlock, nil); return err }},
		{"authorizer", func() error { _, err := p.Authorizer(benchAuthorizer, nil); return err }},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := c.fn(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The FromString helpers are the API the README recommends; compare with BenchmarkParser/fact.
func BenchmarkFromStringFact(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := FromStringFact(benchFact); err != nil {
			b.Fatal(err)
		}
	}
}
