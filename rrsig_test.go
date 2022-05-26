package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestRrsigTiming(t *testing.T) {
	/*
		This RRSIG was created 20220101 00:00:00 UTC it expires 20220130 23:59:59 UTC

		20220101Z000000 has timestamp 1640991600
		20220130Z235959 has timestamp 1643583599
	*/
	rr, _ := dns.NewRR("domain3.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. pFmV17sc+r7P9IcP46ST3pwyxY3/C+TNb5/KedCkU/ePMbO9emJx8Bfq71awwYoo/olFfGL5vbqAjtm/PaHbKA==")

	// For test cases we change now, maxage, minvalid and maxvalid
	cases := []struct {
		Now      uint32
		Minage   uint32
		Maxage   uint32
		Minvalid uint32
		Maxvalid uint32
		Result
	}{
		{1641297600, 4 * 3600, 4 * 24 * 3600, 21 * 24 * 3600, 31 * 24 * 3600, Result{0,0}},      // 2022 01 04 12:00:00, 4 hours, 4 days, 21 days, 31 days - OK
		{1641297600, 4 * 3600, 1 * 24 * 3600, 21 * 24 * 3600, 31 * 24 * 3600, Result{1,0}},      // 2022 01 04 12:00:00, 4 hours, 1 days, 21 days, 31 days - Inception before maxage
		{1641297600, 5 * 24 * 3600, 4 * 24 * 3600, 21 * 24 * 3600, 31 * 24 * 3600, Result{1,0}}, // 2022 01 04 12:00:00, 5 days, 4 days, 21 days, 31 days - Inception after minage
		{1641297600, 4 * 3600, 4 * 24 * 3600, 30 * 24 * 3600, 31 * 24 * 3600, Result{1,0}},      // 2022 01 04 12:00:00, 4 hours, 4 days, 30 days, 31 days - Expiration before minvalid
		{1641297600, 4 * 3600, 4 * 24 * 3600, 21 * 24 * 3600, 21 * 24 * 3600, Result{1,0}},      // 2022 01 01 12:00:00, 4 hours, 4 days, 21 days, 21 days - Expiration after maxvid
		{1641384000, 4 * 3600, 4 * 24 * 3600, 21 * 24 * 3600, 31 * 24 * 3600, Result{1,0}},      // 2022 01 05 12:00:00, 4 hours, 4 days, 21 days, 31 days - Inception before maxage
		{1641006000, 4 * 3600, 4 * 24 * 3600, 21 * 24 * 3600, 31 * 24 * 3600, Result{1,0}},      // 2022 01 01 03:00:00, 4 hours, 4 days, 21 days, 31 days - Inception after minage
	}

	for i, c := range cases {
		minage := c.Now - c.Minage
		maxage := c.Now - c.Maxage
		minvalid := c.Now + c.Minvalid
		maxvalid := c.Now + c.Maxvalid
		if r := checkRRSIGTiming(rr.(*dns.RRSIG), minage, maxage, minvalid, maxvalid); r != c.Result {
			t.Logf("Test case %d: checkRRSIGTiming expected %d errors, and %d warnings, found %d errors and %d warnings.\n", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}

func NewRR(str string) dns.RR {
	rr, _ := dns.NewRR(str)
	return rr
}

var keySet []dns.RR = []dns.RR{
	NewRR("test.	300	IN	DNSKEY	256 3 8 AwEAAdtegl2W8TDwyI8WcCKxiuIJ8rhdQ6c0U37bhCKyqv7qiNuqI4QTMUp5TmgaPFlXK3qhzN1ZfUjkwM9jVaIlkHdb3hVm1cTXJIQcGdgiSaQ+3twiz61InDqyKu6AGo8eHsRivDe42ql8c3A49Sual6WGyAglVXUjgxp4pzqkY7kLlZdcER8h4gDB/4W99m72+f6h8gxb6iiQt/JjOtRVdicukqEMBkXR+N4g/i/WAVHqEfagu5aV2IvtdX+Ahvisyo0+wJLpCFyEY68ekcti8Zw5q5VINpSSoW/Zte6PUi/v11qe9apMf+X95Ku+LZz1fao1wo8XRLq9+1+pKQutlr8= ;{id = 6933 (zsk), size = 2048b}"),
	NewRR("test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}"),
	NewRR("test.	300	IN	DNSKEY	257 3 8 AwEAAalxWv8WFRD49/ueW14s5jqDzNAQ4rrwrusMDWt6Da6Wr/C26Ri+D7QORfD8bbf+oUp4BFk6kdKyze45i8ms0+hZg+pZT7eCdd3sYyixnT+0eAm1sYpy75I+J4aVoZihJOflmDXbiVK7DXXzD0S7qKfx4cJn5DFSWQjufGD8zqOM+lvFjRUzR1mJ+RmiycHdqdMcowhc51drJup2bLHmC5MwzkiL7CbOKDE8offcnxoDOW5356qzHHP4vwT/lQdJq9OLnoGwX0RqCxKICmnKBbtRgPrhgBN1scMbb4xG8pQAru00REf3PuAGS55YFuIDLjrkNYfTuFQ0yuEPA4Ewob0= ;{id = 44164 (ksk), size = 2048b}"),
	NewRR("test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}"),
	NewRR("test.	300	IN	DNSKEY	257 3 15 axT0NyzR1ZpfkCse4Yt5aLP182BV0BcuqFrk5YKFtWg= ;{id = 9455 (ksk), size = 256b}"),
}

var keySigSet []dns.RR = []dns.RR{
	NewRR("test.	300	IN	RRSIG	DNSKEY 8 1 300 20220130235959 20220101000000 44164 test. eChFEXj/HeYyRFJF0j6OTpVDzTNKKIcLvun/hrZsXxeVIRu5FOaQv6gzJ2oBxSN4dOVXO1/m2vNKoKOBBq3bFrJ4F+C+zr4+LlJrILQ/bLWgLEwYqq7AnqTXc19U2zac5nW2Lb6Q7WZjgKL7c6IQOSW6vehnq9PyjtBEf9nou2xEdClHCp9Elt85kKZ1BYe0iEgQJlOJTBm4v45ezfpNrpWl7FYh/OqdR7OAVvyvls+TPeLOFd+9GcBJ1HXmq0h8Gl5mlV8Q9gchZ7G25Ql4qXHvMZY+pJBeQLu1sUzaM6qMo27+5h+Rqe7dQDwa62h8H7wORH/0dvTiawTbrnFcCw=="),
	NewRR("test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. JR8n7cKR7TdH1SUhZKwSLju4qm6y5PHn9N3Flgu//n+/djPXsJY/18N0P+169Sxac8Oq4ZRl9rrnAkXV8kJFBw=="),
	NewRR("test.	300	IN	RRSIG	DNSKEY 15 1 300 20220130235959 20220101000000 9455 test. FojZVsKvLHX6rTSXelesHyRjRo4JXnN7sr1W+r2AGgDYf4yBMaov/dGoEKc+Cv3RH1bgMPBrmhumqKplr4FrBg=="),
}

var nsSet []dns.RR = []dns.RR{
	NewRR("test.	300	IN	NS	a.ns.test."),
	NewRR("test.	300	IN	NS	ns.test."),
}

var nsSigSet []dns.RR = []dns.RR{
	NewRR("test.	300	IN	RRSIG	NS 8 1 300 20220130235959 20220101000000 6933 test. sjCNe6VnWv3HGzkbEpEBluqgADCCe2tpN02BDKWNNcdzEe+3FbyYIAAGiVvi4w3f8Pvumna/ZoLPi/oSjZ5CMXNd1XkE3zT+63YOHYzdTHk1Q3Jy6Ak1W0KhJEACDCVQAAf7miNSxgfxEQ+AKMt0la6cLAO0bUgfHW3BUvQ3k1c0U0Wm3uTvIsZycqEJD9u4hcCLBI7Xw9RkPHlEC8PwQ2Erorh10iYRKlm/bxXe/yIemYYrrkGOPQg2E7RqxJsvxH6ifdhHJzfQJQJaSVOTwPyMv/H98B9lTRHY2HyW3esalGvXLwKSjI9a5Qe9X8HhNlv+3PKzs1i7Ft+KIZCiLg=="),
	NewRR("test.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 test. Fqv8lqk/D1V9DjyCxwhEHxeVTRCC8T4snTlOqwLIVwPmxoZjQ5+lGvMKBQikiyXKgsI/+QOSQ52GFJNLZ4+Bwg=="),
}

var brokenSet1 []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	A	10.0.0.0"),
}
var brokenSigSet1a []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	RRSIG	A 8 2 300 20220130235959 20220101000000 6934 test. IRVLumOQG4owRb0T1yftmJOfUMAtlfFQQ2TAeAOc2Wz3zk+vumkuga+Krta63zcfhuFFhUOLoINkPowwFG8R1ZhjS72nf8wQzcliId1rN5fluNepG8NyxOXi8nh9+t1ihr+d7utdephLSlhUyVlnCTj00BaALCNEj7UmyaYxmEbNutSVCkjkYV044lVX9jomnFHrRiHDeLOceG4WRPQgfDgQGsWdXUsjvNQZYbQcUa3uSET/SV1Qj8ZUfUDUlQm3LzlFM5GxlcKn3eSQkjwdrA1sAuM117tUIDb0QzZG8SGx5YHinbmAk4CqRYYFuifHFSakbTd6C8KHRsEeTye79Q=="),
	NewRR("brokensig.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. pJtIp/nnnEm5dQuBc24OiOOcuGho9dWT9pmVaR+R9wpKx52pj8iLh1RQK2+VoDy6TFi2+/pUzCiIQK9NwOpS6g=="),
}
var brokenSigSet1b []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	RRSIG	A 8 2 300 20220130235959 20220101000000 6933 test. IRVLumOQG4owRb0T1yftmJOfUMAtlfFQQ2TAeAOc2Wz3zk+vumkuga+Krta63zcfhuFFhUOLoINkPowwFG8R1ZhjS72nf8wQzcliId1rN5fluNepG8NyxOXi8nh9+t1ihr+d7utdephLSlhUyVlnCTj00BaALCNEj7UmyaYxmEbNutSVCkjkYV044lVX9jomnFHrRiHDeLOceG4WRPQgfDgQGsWdXUsjvNQZYbQcUa3uSET/SV1Qj8ZUfUDUlQm3LzlFM5GxlcKn3eSQkjwdrA1sAuM117tUIDb0QzZG8SGx5YHinbmAk4CqRYYFuifHFSakbTd6C8KHRsEeTye79Q=="),
	NewRR("brokensig.test.	300	IN	RRSIG	A 15 2 300 20220130235959 20220101000000 11082 test. pJtIp/nnnEm5dQuBc24OiOOcuGho9dWT9pmVaR+R9wpKx52pj8iLh1RQK2+VoDy6TFi2+/pUzCiIQK9NwOpS6g=="),
}
var brokenSigSet1c []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	RRSIG	A 8 2 300 20220130235959 20220101000000 6934 test. IRVLumOQG4owRb0T1yftmJOfUMAtlfFQQ2TAeAOc2Wz3zk+vumkuga+Krta63zcfhuFFhUOLoINkPowwFG8R1ZhjS72nf8wQzcliId1rN5fluNepG8NyxOXi8nh9+t1ihr+d7utdephLSlhUyVlnCTj00BaALCNEj7UmyaYxmEbNutSVCkjkYV044lVX9jomnFHrRiHDeLOceG4WRPQgfDgQGsWdXUsjvNQZYbQcUa3uSET/SV1Qj8ZUfUDUlQm3LzlFM5GxlcKn3eSQkjwdrA1sAuM117tUIDb0QzZG8SGx5YHinbmAk4CqRYYFuifHFSakbTd6C8KHRsEeTye79Q=="),
	NewRR("brokensig.test.	300	IN	RRSIG	A 15 2 300 20220130235959 20220101000000 11082 test. pJtIp/nnnEm5dQuBc24OiOOcuGho9dWT9pmVaR+R9wpKx52pj8iLh1RQK2+VoDy6TFi2+/pUzCiIQK9NwOpS6g=="),
}
var brokenSet2a []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	NSEC	domain.test. A AAAA RRSIG NSEC"),
}
var brokenSet2b []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	NSEC	domain.test. A RRSIG NSEC"),
}
var brokenSigSet2 []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	RRSIG	NSEC 8 2 300 20220130235959 20220101000000 6933 test. qJv5tvPMVo6thkqAIfH4AVEnpqRmqqxXUtXZ2ieSjL/DrLxjC49FjwEYO/U/2yb9xf9dM17bWMU0KGvP+QsQVCwhZVkmD6TgAw+60ZgvFpZHPTA6N7gH8xZMcHjt0r9/kCXnqrfbKu6dATtX2i26qpyUUDOeW7kDDw/zCeEskqPd7OhXAfCwQqNMX0CesFsM5UPyGc8wBn05hKZ6uQIIw5O3xHxzyOOXgQmK4IU4KpAG368QfM4OibNTAJObDrhvlsL5ORDluVhXUAkUMHD7UUbpebrK+4XRi5zwPq/jgx9LjX09WHbqFm8N7ZzXYt98sZtkq0xgc6tLnCeTZc353g=="),
	NewRR("brokensig.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. cVLL4nrkaxwc7c7XrNagWu/XkPFiSvbCVhHpQ8825Wkt99Co1rojjj3PsO8uuLWx/WM3FwzCtTEPZuXhoHkPJg=="),
}

var notRRset []dns.RR = []dns.RR{
	NewRR("brokensig.test.	300	IN	A	10.0.0.0"),
	NewRR("brokensig.test.	300	IN	NSEC	domain.test. A RRSIG NSEC"),
}

func bool2errors(b bool) string {
	if b {
		return "no errors"
	}
	return "errors"
}

func TestCheckSig(t *testing.T) {
	cases := []struct {
		Keys     []dns.RR
		Rrset    []dns.RR
		Rrsigs   []dns.RR
		Result
	}{
		{keySet, keySet, keySigSet, Result{0,0}},
		{keySet, nsSet, nsSigSet, Result{0,0}},
		{keySet, brokenSet1, brokenSigSet1a, Result{1,0}},
		{keySet, brokenSet1, brokenSigSet1b, Result{1,0}},
		{keySet, brokenSet1, brokenSigSet1c, Result{2,0}},
		{keySet, brokenSet2a, brokenSigSet2, Result{2,0}},
		{keySet, brokenSet2b, brokenSigSet2, Result{0,0}},
		{nsSet, keySet, nsSigSet, Result{1,0}},
		{keySet, notRRset, brokenSigSet2, Result{1,0}},
		{keySet, keySet, keySet, Result{1,0}},
	}

	for i, c := range cases {
		if r := checkSig(c.Keys, c.Rrset, c.Rrsigs); r != c.Result {
			t.Logf("Test case %d: checkRRSIG expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}

var checkRRSIGzone = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
glue.example.	300	IN	A	3.4.5.6
glue.example.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. MEtrSiH/nMPwFKuylrRjekVWdG3FNOtCxUQYZUafSz8wuhfumJ+hc65l6bu5VOnwm8sOaFceqdQp9am21hdGBA==
glue.example.	300	IN	AAAA	aced::cafe
glue.example.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 test. F2BJpXIBUGz+FwvlhUw33kwJRFTBhZCSFU8QVwh1vM7YNq6lhp0aVA8eea4quBcCmi7Z2HQkcknN/irJElSyPQ==
glue.example.	300	IN	NSEC	test. A AAAA RRSIG NSEC
glue.example.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. AiuaOOoOLU0QK6pjC/e9Og2UBGkxEZPj5ILFi0Mpno5XtVzlX+15kB2XdmJ/cPkPVWoyP3xocbE8U8+X4EVakw==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
brokensig.test.	300	IN	RRSIG	A 15 2 300 20220130235959 20220101000000 11082 test. Po3QkqUuqKV8ntvaS2ck/n9lP7xHO5SO0YHOnCRA3TaNy56aJ56c6OCUzoJkcqFPtdCDj9s8c8qLnn04tsv1KQ==
brokensig.test.	300	IN	NSEC	domain.test. A NS RRSIG NSEC
brokensig.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. A07yE4jti6q0/njkgX4Da51SeLLjCONguOemfjV4Wg+gRsrwkWEFSfR6BFB0Qu/1QFMkQc1oPrWicKysD5ONvw==
domain.test.	300	IN	NS	noglue.example.
domain.test.	300	IN	NSEC	domain2.test. NS RRSIG NSEC
domain.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. HHyHUD6rHXw0ECKRpOlDEjwKfutvibK5gR0z6y0+3awoixSTidAIhTMb9MgkP0n5nSlU48MzNz28QFNV0YbXBw==
domain2.test.	300	IN	NS	glue.example.
domain2.test.	300	IN	NSEC	domain3.test. NS RRSIG NSEC
domain2.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. o8xWhR8XdaFaT1bPPbhGW3raIyexEesg8XQhcJk1AEGJuchuIvG3WmqhYX9XuK9wwn+VmkxfzjLP0bL2fqK5EQ==
domain3.test.	300	IN	A	4.5.6.7
domain3.test.	300	IN	NS	ns.domain3.test.
domain3.test.	300	IN	NS	domain3.test.
domain3.test.	300	IN	NSEC	domain4.test. NS RRSIG NSEC
domain3.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. kzA/tjekFyG01M3EHoFTDkZBRJqrkqgum4btx+5mHTwdLPOq+YQulsCg1oBxjRmLaHqRiJZkf1YBg3xeU+7t3w==
ns.domain3.test.	300	IN	AAAA	dead::beef
domain4.test.	300	IN	TXT	"blahhblahhblahh"
domain4.test.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 test. EyX5FXX+qe7W6kYPrfYuwpsPCwInRbcLm46TX6elQqK5JpDwv7NRTngh6o0O8YljX/XgVvhttkbHa8sQLhGQ/w==
domain4.test.	300	IN	NSEC	ns.test. TXT RRSIG NSEC
domain4.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. 3a1nqKSDhs//LrX/9yAyS82xJ1LifTJI3Wr+GzHTsIybQAcDqVleMi18VBEpBY9EiqgBK3qrMaq7p53Kjzg6Rw==
ns.test.	300	IN	A	1.2.3.4
ns.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. Uk/tmn1KpVXiIYniKMtvcv6oGLryswnIyNocPFPXgKm7ku22car2WI4MjKyXPsxnjBG9at6qVjhozxg/d/wxfA==
ns.test.	300	IN	AAAA	cafe::bad
ns.test.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 test. EC85JTB9gTSjpGY0pLGi2WYoqxxf3cNqv+fbqT6KnFnE79xDRquo3wDs03GKcDDdP8a/klSuBTeD5Y9nSVyhlw==
ns.test.	300	IN	NSEC	a.ns.test. A AAAA RRSIG NSEC
ns.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. sjun2zx/cmUJBpB4bU7T+q9bW1fDBKd+ytcvxOGeFncKeOPG4cvruQ3KM1GzWodTWZfUKtFa4YjpWog21C5C8w==
a.ns.test.	300	IN	A	2.3.4.5
a.ns.test.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 test. ulxZgDuwK0w3WT6xr7CNLRAVVbpWLVRD1k83T8j3ck85VvDUdHdiKn/4AxswIRzjSmsCEaZeTpQ0kCiyo6Roiw==
a.ns.test.	300	IN	AAAA	bad::cafe
a.ns.test.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 test. Al7RmAjz8m1PQ/N3qv3T1EVdKAgsfl43/SpaM6IQX7ycz2AyBcbUBWyKyqs+oGoOm631d8CmABFxBPES+F/l8w==
a.ns.test.	300	IN	NSEC	glue.example. A AAAA RRSIG NSEC
a.ns.test.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 test. 9iUKFGymVkoYvryeifIi+ATcz2Gk/PcpXHWkUX1qM4ebPbwwOF+yMFYVxvMNtDHNu6+xmRieTikcu9MMYseJjQ==
`

func TestCheckSignatures(t *testing.T) {
	myReader := strings.NewReader(checkRRSIGzone)
	origin, cache := readZonefile(myReader)

	initConfig()

	viper.Set(VERBOSE, VERBOSE_DEBUG)

	expected := Result{5,0}
	viper.Set("now", "2022-01-04T12:00:00Z")
	if r := checkRRSIG(cache, origin); r != expected {
		t.Logf("checkSignatures expected  %d errors and %d warnings, found %d errors and %d warnings.\n.", expected.errors, expected.warnings, r.errors, r.warnings)
		t.Fail()
	}

	viper.Set("now", "2022-21-59T12:00:00Z")
	expected = Result{1,0}
	if r := checkRRSIG(cache, origin); r != expected {
		t.Logf("checkSignatures expected  %d errors and %d warnings, found %d errors and %d warnings.\n.", expected.errors, expected.warnings, r.errors, r.warnings)
		t.Fail()
	}

	viper.Set("now", nil)
	expected = Result{39,0}
	if r := checkRRSIG(cache, origin); r != expected {
		t.Logf("checkSignatures expected  %d errors and %d warnings, found %d errors and %d warnings.\n.", expected.errors, expected.warnings, r.errors, r.warnings)
		t.Fail()
	}
}
