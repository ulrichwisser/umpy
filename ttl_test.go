package main

import (
	"testing"
)

func TestStringToTTL(t *testing.T) {
	cases := []struct {
		TtlString    string
    ExpectedUint32 uint32
    ExpectedBool bool
	}{
    {"", 0, true},
    {"1a", 0, false},
    {"77", 77, true},
    {"1h", 3600, true},
    {"1m", 60, true},
    {"1d1m7h", 111660, true},
    {"3w1s7m5h", 1832821, true},
    {"129346s", 129346, true},
    {"0h", 0, true},
    {"0W0D0H0M1S", 1, true},
    {"1W2d3h4M5s", 788645, true},
    {"1W2d3j4M5s", 0, false},
    {"1W2d3h4M5ss", 788645, true},
	}

	for _, c := range cases {
    ttl,success:=stringToTTL(c.TtlString)
		if (ttl != c.ExpectedUint32) || (success != c.ExpectedBool) {
			t.Logf("For value %s: expected %d,%v got %d,%v\n", c.TtlString, c.ExpectedUint32,c.ExpectedBool,ttl,success)
			t.Fail()
			continue
		}
	}
}
