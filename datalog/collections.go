// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Array is an ordered sequence of terms of any type (datalog v3.3).
type Array []Term

func (Array) Type() TermType { return TermTypeArray }

func (a Array) Equal(t Term) bool {
	other, ok := t.(Array)
	if !ok || len(a) != len(other) {
		return false
	}
	for i := range a {
		if !a[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// HasPrefix reports whether a starts with the elements of prefix.
func (a Array) HasPrefix(prefix Array) bool {
	if len(prefix) > len(a) {
		return false
	}
	return Array(a[:len(prefix)]).Equal(prefix)
}

// HasSuffix reports whether a ends with the elements of suffix.
func (a Array) HasSuffix(suffix Array) bool {
	if len(suffix) > len(a) {
		return false
	}
	return Array(a[len(a)-len(suffix):]).Equal(suffix)
}

func (a Array) contains(t Term) bool {
	for _, e := range a {
		if e.Equal(t) {
			return true
		}
	}
	return false
}

func (a Array) String() string {
	strs := make([]string, len(a))
	for i, e := range a {
		strs[i] = e.String()
	}
	return fmt.Sprintf("[%s]", strings.Join(strs, ", "))
}

// MapEntry is one key/value pair of a Map. The key is an Integer or a
// String.
type MapEntry struct {
	Key   Term
	Value Term
}

// Map associates Integer or String keys with terms of any type (datalog
// v3.3). Entries are kept sorted by key, integers first, so that two maps
// with the same entries are equal and print the same.
type Map []MapEntry

// NewMap builds a map; a key given twice keeps its last value.
func NewMap(entries ...MapEntry) Map {
	m := make(Map, 0, len(entries))
	for _, e := range entries {
		m = m.with(e)
	}
	return m
}

func (m Map) with(e MapEntry) Map {
	i, found := slices.BinarySearchFunc(m, e.Key, func(entry MapEntry, key Term) int {
		return compareMapKeys(entry.Key, key)
	})
	if found {
		res := slices.Clone(m)
		res[i].Value = e.Value
		return res
	}
	return slices.Insert(slices.Clone(m), i, e)
}

// compareMapKeys orders integers before strings, then by value.
func compareMapKeys(a, b Term) int {
	switch ka := a.(type) {
	case Integer:
		if kb, ok := b.(Integer); ok {
			return cmp.Compare(ka, kb)
		}
		return -1
	case String:
		if kb, ok := b.(String); ok {
			return cmp.Compare(ka, kb)
		}
		return 1
	default:
		return 0
	}
}

// IsMapKey reports whether a term may be a map key.
func IsMapKey(t Term) bool {
	switch t.(type) {
	case Integer, String:
		return true
	}
	return false
}

func (Map) Type() TermType { return TermTypeMap }

func (m Map) Equal(t Term) bool {
	other, ok := t.(Map)
	if !ok || len(m) != len(other) {
		return false
	}
	for i := range m {
		if !m[i].Key.Equal(other[i].Key) || !m[i].Value.Equal(other[i].Value) {
			return false
		}
	}
	return true
}

// Get returns the value for the key, or nil when absent.
func (m Map) Get(key Term) Term {
	for _, e := range m {
		if e.Key.Equal(key) {
			return e.Value
		}
	}
	return nil
}

func (m Map) String() string {
	strs := make([]string, len(m))
	for i, e := range m {
		strs[i] = fmt.Sprintf("%s: %s", e.Key, e.Value)
	}
	return fmt.Sprintf("{%s}", strings.Join(strs, ", "))
}
