package main

import (
	"strings"
	"testing"

	//"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var dsDefault []struct {
	Name  string
	Value bool
} = []struct {
	Name  string
	Value bool
}{
	// Digest Types
	{"SHA1", false},
	{"SHA256", true},
	{"GOST94", false},
	{"SHA384", true},

	// Algorithms
	{"RSAMD5", false},
	{"DH", false},
	{"DSA", false},
	{"RSASHA1", false},
	{"DSA-NSEC3-SHA1", false},
	{"RSASHA1-NSEC3-SHA1", false},
	{"RSASHA256", true},
	{"RSASHA512", true},
	{"ECC-GOST", false},
	{"ECDSAP256SHA256", true},
	{"ECDSAP384SHA384", true},
	{"ED25519", true},
	{"ED448", true},
	{"INDIRECT", false},
	{"PRIVATEDNS", false},
	{"PRIVATEOID", false},
}

func SetDefaultConf() {
	for _, o := range dsDefault {
		viper.Set(o.Name, o.Value)
	}
}

func TestDSdefault(t *testing.T) {

	for _, o := range dsDefault {
		if !viper.IsSet(o.Name) && !o.Value {
			continue
		}
		if !viper.IsSet(o.Name) && !o.Value {
			t.Logf("No default set for %s, but should be allowed", o.Name)
			t.Fail()
			continue
		}
		if viper.GetBool(o.Name) != o.Value {
			t.Logf("Default for %s is unexpectedly %s", o.Name, bool2allow(!o.Value))
			t.Fail()
		}
	}

	// restore configuration
	viper.Reset()
	initConfig()
}

var dsZoneString string = `
test00.example.  300 IN DS 12345   1  0
test00.example.  300 IN DS 12345   0  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test00.example.  300 IN NS ns1.glue.
test01.example.  300 IN DS 12345   1  1 123456789abcdef67890123456789abcdef67890
test01.example.  300 IN DS 12345   1  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test01.example.  300 IN NS ns1.glue.
test02.example.  300 IN DS 12345   1  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test02.example.  300 IN DS 12345   2  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test03.example.  300 IN DS 12345   1  3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B2071398F
test03.example.  300 IN DS 12345   3  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test04.example.  300 IN DS 12345   1  4 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6
test04.example.  300 IN DS 12345   4  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test05.example.  300 IN DS 12345   1 99 123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890
test05.example.  300 IN DS 12345   5  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test06.example.  300 IN DS 12345   6  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test07.example.  300 IN DS 12345   7  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test08.example.  300 IN DS 12345   8  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test08.example.  300 IN NS ns1.glue.
test09.example.  300 IN DS 12345   9  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test10.example.  300 IN DS 12345  10  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test11.example.  300 IN DS 12345  11  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test12.example.  300 IN DS 12345  12  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test13.example.  300 IN DS 12345  13  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test14.example.  300 IN DS 12345  14  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test15.example.  300 IN DS 12345  15  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test16.example.  300 IN DS 12345  16  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test17.example.  300 IN DS 12345  17  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test123.example. 300 IN DS 12345 123  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test252.example. 300 IN DS 12345 252  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test253.example. 300 IN DS 12345 253  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test254.example. 300 IN DS 12345 254  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
test255.example. 300 IN DS 12345 255  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
testAAA.example. 300 IN A 127.0.0.1
`

func TestCheckDS(t *testing.T) {
	myReader := strings.NewReader(dsZoneString)
	_, cache := readZonefile(myReader)

	SetDefaultConf()

	// default config
	dsErrors := checkDS(cache, "")
	if dsErrors.errors != 47 {
		t.Logf("Expected 47 errors, got %d errors", dsErrors)
		t.Fail()
	}

	// custom config
	viper.Set("GOST94", true)
	dsErrors = checkDS(cache, "")
	if dsErrors.errors != 46 {
		t.Logf("Expected 46 errors, got %d errors", dsErrors)
		t.Fail()
	}
	viper.Set("RSAMD5", true)
	dsErrors = checkDS(cache, "")
	if dsErrors.errors != 39 {
		t.Logf("Expected 39 errors, got %d errors", dsErrors)
		t.Fail()
	}
	viper.Set("ED448", false)
	dsErrors = checkDS(cache, "")
	if dsErrors.errors != 40 {
		t.Logf("Expected 40 errors, got %d errors", dsErrors)
		t.Fail()
	}

	// restore configuration
	viper.Reset()
	initConfig()
}
