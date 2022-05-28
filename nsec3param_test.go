package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

var paramString0 string = `
test.example. 300 IN NS ns.example.
`
var paramString1 string = `
test.example. 300 IN NSEC3PARAM 1 0 0 -
test.example. 300 IN NSEC3PARAM 2 0 0 -
`
var paramString2 string = `
test.example. 300 IN NSEC3PARAM 0 0 0 -
`
var paramString3 string = `
test.example. 300 IN NSEC3PARAM 1 1 0 -
`
var paramString4 string = `
test.example. 300 IN NSEC3PARAM 1 0 1 -
`
var paramString5 string = `
test.example. 300 IN NSEC3PARAM 1 0 0 00AA
`
var paramString6 string = `
test.example. 300 IN NSEC3PARAM 1 0 0 -
`
var paramString7 string = `
test.example. 300 IN NSEC3PARAM 2 1 1 00AA
`
var paramString8 string = `
test.example. 300 IN NSEC3PARAM 1 0 11 -
`
var paramString9 string = `
test.example. 300 IN NSEC3PARAM 2 255 99 CCDDEEFF
`

func TestCheckNSEC3PARAM(t *testing.T) {
	cases := []struct {
		Zone             string
		ExpectedErrors   uint32
		ExpectedWarnings uint32
	}{
		{paramString0, 1, 0},
		{paramString1, 1, 0},
		{paramString2, 1, 0},
		{paramString3, 1, 0},
		{paramString4, 0, 1},
		{paramString5, 0, 1},
		{paramString6, 0, 0},
		{paramString7, 2, 2},
		{paramString8, 1, 0},
		{paramString9, 3, 1},
	}

	initConfig()

	for i, c := range cases {
		fmt.Println("TESTCASE", i)
		myReader := strings.NewReader(c.Zone)
		_, cache := readZonefile(myReader)
		if r := checkNSEC3PARAM(cache, "test.example."); r.errors != c.ExpectedErrors || r.warnings != c.ExpectedWarnings {
			t.Logf("Test case %d: checkNSEC3PARAM found %d errors and %d warnings, expected %d errors and %d warnings.", i, r.errors, r.warnings, c.ExpectedErrors, c.ExpectedWarnings)
			t.Fail()
		}
	}

	viper.Reset()
}
