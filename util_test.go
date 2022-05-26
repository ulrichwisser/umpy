package main

import (
	"fmt"
	"strings"
	"testing"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const zoneString string = `
test. 300 IN SOA master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test. 300 IN NS ns.test.
ns.test. 300 IN A 1.2.3.4
ns.test. 300 IN AAAA cafe::bad
test. 300 IN NS a.ns.test.
a.ns.test. 300 IN A 2.3.4.5
a.ns.test. 300 IN AAAA bad::cafe
test. 300 IN NS a.ns.test.
domain.test. 300 IN NS noglue.example.
domain2.test. 300 IN NS glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
domain3.test. 300 IN NS domain3.test.
domain3.test. 300 IN NS ns.domain3.test.
domain3.test. 300 IN A 4.5.6.7
ns.domain3.test. 300 IN AAAA dead::beef
domain4.test. 300 IN TXT "blahhblahhblahh"
`

const nsecString = `
test.			7200	IN	NSEC	0.test. NS SOA TXT RRSIG NSEC DNSKEY
test.			7200	IN	RRSIG	NSEC 8 1 7200 20220305192100 20220219151056 30015 test. 1cvoiwe4MMsJPj2Cx8tTRxX8E/8qjkFZ4qsFqZzyFJhxeyc5DxCrbEG6 o2t9zWkTCi6LPdDLrcmiM03zUI20MkJhurtZe53vnuSeE6XZtkaOdT/m DcAOqh+xjXPtTG/4OTE0IumjXDeCggWgPLBaImyU6IzD08lnYVfNWD5S UtJJC0gljQRuOkTg9YyrbtDtGqnUHrokUqO0mYcEt6gA6ToTLg2PWeVO ewdQ05gd6IkbBfMqDE8ThJBKco49FoKX9zunIDGX07SboDOVK/1ugyG0 GUwfetjGR3Vp19u9I7Vu/YYKbRL+3LxqGA2Wm9c4JO0OkP/DbNvPVTnE Xvokvw==
domain.test.		7200	IN	NSEC	domain2.test. NS DS RRSIG NSEC
domain.test.		7200	IN	RRSIG	NSEC 8 2 7200 20220303191459 20220218081055 30015 test. HAkHyHdaJpM04TfTNQVRMp9Q0hzK9AceoQ0pisEAMeIvFIjSNd6MrrMe G19IgIBLgvqrRZ+gwBfPGnZnuRw/wkK8atXZ5w7MAO35q7hpt7h9aWDr UYYi338ybfVlFUgeVYa9hUO43aWrgi8VR3FfK6LKKk2DGnGXD5g5vypH OlvIMcwRbznxtkz8MYTV3f+y7oTXXg+2lDzJT9bnKhXwkLUiFE+cj/Aa +W7zVafa7NByC/L+7t2ppCI7Q67PeeCMZk7xkDzao2rjA/GOw8exyFtF H6pUq1ODS/g8XXwRxw/09a86hwy3oZU/A0fCHgg7cowcnEEFk7O8o4vf rYKGXg==
`

const nsec3String = `
pf5ggff0gs9sg52piteldh74o3gbnp36.test. 600 IN NSEC3 1 1 5 E67CF0D5AAC2073E PF5GUMKTO0BFON5B55R5AJS601HR22LS NS SOA TXT RRSIG DNSKEY NSEC3PARAM
pf5ggff0gs9sg52piteldh74o3gbnp36.test. 600 IN RRSIG NSEC3 8 2 600 20220305025421 20220218160733 31851 test. p+dfRzeb19qZbBrVR3zKSni2MHl+0AYAl1vQV8xpv/oo/1aUZ9WUN7FR puRK8ZE6mDkPyoWk95/uIzy2CAgF2l59I3cIAua3dDqLvIROjOmP4i2l F0/TRr1IiiQIooQYu25RjSmfRBB/MuPDTFx4xyGhrgWQcltDc5HI9lM9 UA8=
33m18ivfil53cbo8moau57tvu1635d5i.test. 600 IN NSEC3 1 1 5 E67CF0D5AAC2073E 33M1CHG9D15CJJ83KNM8QO4D19HAEEHO NS DS RRSIG
33m18ivfil53cbo8moau57tvu1635d5i.test. 600 IN RRSIG NSEC3 8 2 600 20220302175258 20220216040734 31851 test. JGEbMjGh9MfGBqI9dfP+n3d/4g8e4+zX/NiJaKBA9yqlrnLCFQtnlZvW dWt9jORvlqFheD1hgbfqLpaN37BQE3LjhNjDA1z+BtpYN/zmPrXK45ac CAZy1lkFjUfdTPQ9yYbZkQYrvA6uvkgID8Y7rY1zURuW2vUXRojvcOeu iAk=
53f6us68suhvkl2hh30g8hqqqep9gs8a.test. 600 IN NSEC3 1 1 5 E67CF0D5AAC2073E 53F7NJ7QK3UPQAFDGNUDBA652L2LSRMA NS DS RRSIG
53f6us68suhvkl2hh30g8hqqqep9gs8a.test. 600 IN RRSIG NSEC3 8 2 600 20220304051942 20220218060735 31851 test. aduY4ZddnmCNVr328cy+Q7wVt2EXcFXdfODp1awPJPf3bBM5cPhvsgF/ 1+xsLsKC7r08sNDjm7qUxryapA4h0qMwjjMp6fDyjq3Kx3JLG2jGl6NU /SDIYzBKYMX0D252y2/p29C06HJXmruNK29cfpw7nF7E0hoo4F2Qq7T1 pdM=
`

func TestRevert(t *testing.T) {
	cases := []struct {
		Fqdn     string
		Expected []string
	}{
		{".", []string{}},
		{"test", []string{"test"}},
		{"test.", []string{"test"}},
		{"test2.test.", []string{"test", "test2"}},
		{"test3.test2.test.", []string{"test", "test2", "test3"}},
		{"test4.test3.test2.test.", []string{"test", "test2", "test3", "test4"}},
	}

	for _, c := range cases {
		labels := Reverse(c.Fqdn)
		if len(labels) != len(c.Expected) {
			t.Log("Expected ", c.Expected, " got ", labels)
			t.Fail()
			continue
		}
		for i := 0; i < len(labels); i += 1 {
			if labels[i] != c.Expected[i] {
				t.Log("Reverse of ", c.Fqdn, " is wrong in position ", i, ". Expected ", c.Expected[i], " got ", labels[i])
				t.Fail()
			}
		}
	}
}

func TestIsDelegated(t *testing.T) {
	myReader := strings.NewReader(zoneString)
	origin, cache := readZonefile(myReader)

	cases := []struct {
		Label    string
		Expected bool
	}{
		{".", true},
		{"test", true},
		{"test.", false},
		{"ns.test.", false},
		{"a.ns.test.", false},
		{"domain.test.", true},
		{"domain2.test.", true},
		{"domain3.test.", true},
		{"ns.domain3.test.", true},
		{"domain4.test.", false},
		{"noglue.example.", true},
		{"glue.example.", true},
		{"notthere", true},
	}

	for _, c := range cases {
		b := isDelegated(c.Label, cache, origin)
		if b != c.Expected {
			t.Log("isDelegated of ", c.Label, " is ", b, " expected ", c.Expected)
			t.Fail()
		}
	}
}

func TestGetLabels(t *testing.T) {
	myReader := strings.NewReader(zoneString)
	_, cache := readZonefile(myReader)

	expected := []string{
		"glue.example.",
		"test.",
		"domain.test.",
		"domain2.test.",
		"domain3.test.",
		"ns.domain3.test.",
		"domain4.test.",
		"ns.test.",
		"a.ns.test.",
	}

	labels := getLabels(cache)
	if len(labels) != len(expected) {
		t.Log("getLabels returned ", len(labels), " labels, expected ", len(expected))
		t.Log(labels)
		t.Fail()
		return
	}

	for i := 0; i < len(labels); i += 1 {
		if labels[i] != expected[i] {
			t.Log("Label ", i, " is ", labels[i], " expected ", expected[i])
			t.Fail()
		}
	}
}

func TestHasNSEC(t *testing.T) {
	cases := []struct {
		Zone     string
		Expected bool
	}{
		{zoneString, false},
		{zoneString + nsecString, true},
		{zoneString + nsec3String, false},
		{zoneString + nsecString + nsec3String, true},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		_, cache := readZonefile(myReader)
		if hasNSEC(cache) != c.Expected {
			t.Log("Test case ", i, ": hasNSEC found NSEC where no NSEC records are present.")
			t.Fail()
		}
	}
}

func TestHasNSEC3(t *testing.T) {
	cases := []struct {
		Zone     string
		Expected bool
	}{
		{zoneString, false},
		{zoneString + nsecString, false},
		{zoneString + nsec3String, true},
		{zoneString + nsecString + nsec3String, true},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		_, cache := readZonefile(myReader)
		if hasNSEC3(cache) != c.Expected {
			t.Log("Test case ", i, ": hasNSEC3 found NSEC3 where no NSEC3 records are present.")
			t.Fail()
		}
	}
}

func TestHash2String(t *testing.T) {
	cases := []struct {
		Dt       uint8
		Expected string
	}{
		{0, "DIGESTTYPE0"},
		{1, "SHA1"},
		{2, "SHA256"},
		{3, "GOST94"},
		{4, "SHA384"},
		{5, "SHA512"},
	}

	for i, c := range cases {

		if dtstr := hash2string(c.Dt); dtstr != c.Expected {
			t.Logf("Test case %d hash2str(%d) returned %s, expected %s", i, c.Dt, dtstr, c.Expected)
			t.Fail()
		}
	}

	for i := 6; i <= 255; i++ {
		expected := fmt.Sprintf("DIGESTTYPE%d", i)
		if dtstr := hash2string(uint8(i)); dtstr != expected {
			t.Logf("Test case %d hash2str(%d) returned %s, expected %s", i, i, dtstr, expected)
			t.Fail()
		}
	}
}

func TestAlgorithm2String(t *testing.T) {
	cases := []struct {
		Algorithm       uint8
		Expected string
	}{
		{0, "ALGORITHM0"},
		{1, "RSAMD5"},
		{2, "DH"},
		{3, "DSA"},
		{4, "ALGORITHM4"},
		{5, "RSASHA1"},
		{6, "DSA-NSEC3-SHA1"},
		{7, "RSASHA1-NSEC3-SHA1"},
		{8, "RSASHA256"},
		{9, "ALGORITHM9"},
		{10, "RSASHA512"},
		{11, "ALGORITHM11"},
		{12, "ECC-GOST"},
		{13, "ECDSAP256SHA256"},
		{14, "ECDSAP384SHA384"},
		{15, "ED25519"},
		{16, "ED448"},
		{252, "INDIRECT"},
		{253, "PRIVATEDNS"},
		{254, "PRIVATEOID"},
		{255, "ALGORITHM255"},
	}

	for i, c := range cases {

		if dtstr := algorithm2string(c.Algorithm); dtstr != c.Expected {
			t.Logf("Test case %d hash2str(%d) returned %s, expected %s", i, c.Algorithm, dtstr, c.Expected)
			t.Fail()
		}
	}

	for i := 17; i <= 251; i++ {
		expected := fmt.Sprintf("ALGORITHM%d", i)
		if dtstr := algorithm2string(uint8(i)); dtstr != expected {
			t.Logf("Test case %d hash2str(%d) returned %s, expected %s", i, i, dtstr, expected)
			t.Fail()
		}
	}
}

func TestOkAlgorithm(t *testing.T) {
	cases := []struct {
		RR       string
		Expected bool
	}{
		{"test00.example  300 IN DS 12345   0 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // delete ds
		{"test01.example  300 IN DS 12345   1 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // RSAMD5
		{"test02.example  300 IN DS 12345   2 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // DH
		{"test03.example  300 IN DS 12345   3 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // DSA
		{"test04.example  300 IN DS 12345   4 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Reserved
		{"test05.example  300 IN DS 12345   5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // RSASHA1
		{"test06.example  300 IN DS 12345   6 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // DSA-NSEC3-SHA1
		{"test07.example  300 IN DS 12345   7 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // RSASHA1-NSEC3-SHA1
		{"test08.example  300 IN DS 12345   8 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // RSASHA256
		{"test09.example  300 IN DS 12345   9 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Reserved
		{"test10.example  300 IN DS 12345  10 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // RSASHA512
		{"test11.example  300 IN DS 12345  11 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Reserved
		{"test12.example  300 IN DS 12345  12 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // ECC-GOST
		{"test13.example  300 IN DS 12345  13 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // ECDSAP256SHA256
		{"test14.example  300 IN DS 12345  14 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // ECDSAP384SHA384
		{"test15.example  300 IN DS 12345  15 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // ED25519
		{"test16.example  300 IN DS 12345  16 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},  // ED448
		{"test17.example  300 IN DS 12345  17 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Unassigned
		{"test123.example 300 IN DS 12345 123 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Reserved
		{"test252.example 300 IN DS 12345 252 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // INDIRECT
		{"test253.example 300 IN DS 12345 253 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // PRIVATEDNS
		{"test254.example 300 IN DS 12345 254 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // PRIVATEOID
		{"test255.example 300 IN DS 12345 255 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", false}, // Reserved
	}

	initConfig()

	for _, c := range cases {
		rr, _ := dns.NewRR(c.RR)
		ds := (rr).(*dns.DS)

		// default config
		if okAlgorithm(ds.Algorithm) != c.Expected {
			t.Logf("Test1: DS Algorithm %s (%d) unexpectedly %s", algorithm2string(ds.Algorithm), ds.Algorithm, bool2allow(!c.Expected))
			t.Fail()
		}

		viper.Set(algorithm2string(ds.Algorithm), true)
		if !okAlgorithm(ds.Algorithm) {
			t.Logf("Test2: DS Algorithm %s (%d) unexpectedly %s", algorithm2string(ds.Algorithm), ds.Algorithm, bool2allow(false))
			t.Fail()
		}

		viper.Set(algorithm2string(ds.Algorithm), false)
		if okAlgorithm(ds.Algorithm) {
			t.Logf("Test3: DS Algorithm %s (%d) unexpectedly %s", algorithm2string(ds.Algorithm), ds.Algorithm, bool2allow(true))
			t.Fail()
		}
	}
	viper.Reset()
}

func TestOkDigestType(t *testing.T) {
	cases := []struct {
		RR       string
		Expected bool
	}{
		{"test00.example 300 IN DS 12345 1 0", false},
		{"test01.example 300 IN DS 12345 1 1 123456789abcdef67890123456789abcdef67890", false},
		{"test02.example 300 IN DS 12345 1 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", true},
		{"test03.example 300 IN DS 12345 1 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B2071398F", false},
		{"test04.example 300 IN DS 12345 1 4 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6 ", true},
		{"test05.example 300 IN DS 12345 1 99 123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890123456789abcdef67890", false},
	}

	initConfig()

	for _, c := range cases {
		rr, _ := dns.NewRR(c.RR)
		ds := (rr).(*dns.DS)

		// default config
		if okDigestType(ds.DigestType) != c.Expected {
			t.Logf("DigestType %s (%d) unexpectedly %s", hash2string(ds.DigestType), ds.DigestType, bool2allow(!c.Expected))
			t.Fail()
			continue
		}

		viper.Set(hash2string(ds.DigestType), true)
		if !okDigestType(ds.DigestType) {
			t.Logf("DigestType %s (%d) unexpectedly %s", hash2string(ds.DigestType), ds.DigestType, bool2allow(false))
			t.Fail()
			continue
		}

		viper.Set(hash2string(ds.DigestType), false)
		if okDigestType(ds.DigestType) {
			t.Logf("DigestType %s (%d) unexpectedly %s", hash2string(ds.DigestType), ds.DigestType, bool2allow(true))
			t.Fail()
			continue
		}
	}
	viper.Reset()
}
