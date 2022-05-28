package main

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

var nsecZone0 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. WMA4R0HY1Kd9lPAwfnEbFJsvCNXNNGaKd0H1qSuVYh2sHlvHVPXyqKoclEZauYX/P4dEezwW1Ow15LIyJKbNOA==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 test. Bc/kRNMbUO7fWz0zW7EnkCliA18qQhkBBPHwKBqW8DS5mpSqmRQxu12doazex/v4bbR9uoj6BsAN070dcxFq7w==
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. oySh9y2KXbVtUgIMVwhcSHbYnEKb5zegRh/3DG9wylfI70ptdH+UVDLvujCixgCR3NxxDq5nQsrw9MW+uDLzYA==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. m8gEEWBy1qNLHkIwjFm3Z0eXQzh9yiVsK+FLHVD/cVDU3BN06+5AMBiGu9yDUPCq1W1CHyKI+LUU1cWTqk0qlg==
brokensig.test.	300	IN	A	10.0.0.0
brokensig.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. ogZaRb7PxJTtOrpMdw4nYMQaXIX+uz97/hnYBim9WHxLMt+Rj+kjjgKw9edpaeU4fsZCXFtIjggOQVrI2FA+zg==
brokensig.test.	300	IN	NSEC	domain.test. A RRSIG NSEC
brokensig.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. JZFWTtPt5SKbVIzdV2TbO/ktX7jQbe0VdgS7FZpJgg2DaBvgUp/s+yfaO29N66OMGQI9Y7vWY8Eh826EtHCepQ==
domain.test.	300	IN	NS	noglue.example.
domain.test.	300	IN	NSEC	domain2.test. NS RRSIG NSEC
domain.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. LtInINyNBeCfIqcf54rC4TvR4xWNajylULWSL8BU/EyY/II1sCrWLorl8XUl/nZFhM5sCEXzqJTm+nRyeR0tnA==
domain2.test.	300	IN	NS	glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
domain2.test.	300	IN	NSEC	domain3.test. NS RRSIG NSEC
domain2.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. d+FhpZA4SVAyGvMadvcuqk2O2LVYzc5/k6VbsKoxpbg82lsYski8ThBpGDs8vKM1UZwdggyIohrUhwFCdd5QxA==
domain3.test.	300	IN	A	4.5.6.7
domain3.test.	300	IN	NS	ns.domain3.test.
domain3.test.	300	IN	NS	domain3.test.
domain3.test.	300	IN	NSEC	domain4.test. NS RRSIG NSEC
domain3.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. Qyvh8+uA8Y6mdVZGxeY/58E7ZUOmWRQEXXSDw7l6nKwF6ARWxnUxPzXdI4YQf6K8gV0lfnyU1H9e871CdH8+wg==
ns.domain3.test.	300	IN	AAAA	dead::beef
domain4.test.	300	IN	TXT	"blahhblahhblahh"
domain4.test.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 test. pAmD3Xyn1cJo1TGW/Pgxm9NGO2KtDl6H5TuLSBpD4QhIgE7pvD7KOnqMvbRkN7p/XiF4oIE50aeVOz0yVYt8Sw==
domain4.test.	300	IN	NSEC	ns.test. TXT RRSIG NSEC
domain4.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. p4u+q9tj80uohqMY1UWP4hbVS7fe1nJXgkXsQQFNVarfZbKx+pQD5oxCAk/sdYen82rF93rr74ON3wWT8vhrLw==
ns.test.	300	IN	A	1.2.3.4
ns.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. 8susQ9PcknV86vchocRejC8zf77Yacyp7FbLL4neS3K2QKkGDW2k3jUbssAJzLuyddPdjWcdyUgSnnjAhx6EPw==
ns.test.	300	IN	AAAA	cafe::bad
ns.test.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 test. ANXH1JnaHO+dtvOrwRPgeecQmKg4JwYd7Fmpezz00HUC5uHeb5/p38nm+X4SEAe2AyoG94a4sMt4/fZ9exjJ/g==
ns.test.	300	IN	NSEC	a.ns.test. A AAAA RRSIG NSEC
ns.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. B6HqjRiv3Iy+84ti9nPXkp+ZYikJF7TxpXWd+zpDWJnORxT6+Yy3yfTbikE8s1oMq25L8UzWh1SByBcklzEoag==
a.ns.test.	300	IN	A	2.3.4.5
a.ns.test.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 test. GQ+I6G4Th64EEaSnaFwm1Y1xNJ3TVBUXVEv4XqhulzI0VPe3B+v0wEojp7TEdT17IIZIRRf8IZ5v+7iiPEW9Dw==
a.ns.test.	300	IN	AAAA	bad::cafe
a.ns.test.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 test. 5KqoblqjalCrazgA+/ShmaUrqvRkcA2ZEYeJMLJUQky4MOJep/NHos4FpnwWk7pVGxVYdiSD2I7jqNWQIQDaUA==
a.ns.test.	300	IN	NSEC	test. A AAAA RRSIG NSEC
a.ns.test.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 test. kYCdRpsQfO0n9qi+Gn5aOvWnefz+gmJ6m6Van7AxOxYWrL0BQQnDSSDEdtKDhInkpZrPzKyNYUYXK34Moy52wQ==
`
var nsecZone1 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. WMA4R0HY1Kd9lPAwfnEbFJsvCNXNNGaKd0H1qSuVYh2sHlvHVPXyqKoclEZauYX/P4dEezwW1Ow15LIyJKbNOA==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 test. Bc/kRNMbUO7fWz0zW7EnkCliA18qQhkBBPHwKBqW8DS5mpSqmRQxu12doazex/v4bbR9uoj6BsAN070dcxFq7w==
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. oySh9y2KXbVtUgIMVwhcSHbYnEKb5zegRh/3DG9wylfI70ptdH+UVDLvujCixgCR3NxxDq5nQsrw9MW+uDLzYA==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. m8gEEWBy1qNLHkIwjFm3Z0eXQzh9yiVsK+FLHVD/cVDU3BN06+5AMBiGu9yDUPCq1W1CHyKI+LUU1cWTqk0qlg==
brokensig.test.	300	IN	A	10.0.0.0
brokensig.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. ogZaRb7PxJTtOrpMdw4nYMQaXIX+uz97/hnYBim9WHxLMt+Rj+kjjgKw9edpaeU4fsZCXFtIjggOQVrI2FA+zg==
brokensig.test.	300	IN	NSEC	domain.test. A RRSIG NSEC
brokensig.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. JZFWTtPt5SKbVIzdV2TbO/ktX7jQbe0VdgS7FZpJgg2DaBvgUp/s+yfaO29N66OMGQI9Y7vWY8Eh826EtHCepQ==
domain.test.	300	IN	NS	noglue.example.
domain.test.	300	IN	NSEC	domain2.test. NS RRSIG NSEC
domain.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. LtInINyNBeCfIqcf54rC4TvR4xWNajylULWSL8BU/EyY/II1sCrWLorl8XUl/nZFhM5sCEXzqJTm+nRyeR0tnA==
domain2.test.	300	IN	NS	glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
domain2.test.	300	IN	NSEC	domain3.test. NS RRSIG NSEC
domain2.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. d+FhpZA4SVAyGvMadvcuqk2O2LVYzc5/k6VbsKoxpbg82lsYski8ThBpGDs8vKM1UZwdggyIohrUhwFCdd5QxA==
domain3.test.	300	IN	A	4.5.6.7
domain3.test.	300	IN	NS	ns.domain3.test.
domain3.test.	300	IN	NS	domain3.test.
domain3.test.	300	IN	NSEC	ns.test. NS RRSIG NSEC
domain3.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. Qyvh8+uA8Y6mdVZGxeY/58E7ZUOmWRQEXXSDw7l6nKwF6ARWxnUxPzXdI4YQf6K8gV0lfnyU1H9e871CdH8+wg==
ns.domain3.test.	300	IN	AAAA	dead::beef
domain4.test.	300	IN	TXT	"blahhblahhblahh"
domain4.test.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 test. pAmD3Xyn1cJo1TGW/Pgxm9NGO2KtDl6H5TuLSBpD4QhIgE7pvD7KOnqMvbRkN7p/XiF4oIE50aeVOz0yVYt8Sw==
ns.test.	300	IN	A	1.2.3.4
ns.test.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 test. 8susQ9PcknV86vchocRejC8zf77Yacyp7FbLL4neS3K2QKkGDW2k3jUbssAJzLuyddPdjWcdyUgSnnjAhx6EPw==
ns.test.	300	IN	AAAA	cafe::bad
ns.test.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 test. ANXH1JnaHO+dtvOrwRPgeecQmKg4JwYd7Fmpezz00HUC5uHeb5/p38nm+X4SEAe2AyoG94a4sMt4/fZ9exjJ/g==
ns.test.	300	IN	NSEC	a.ns.test. A AAAA RRSIG NSEC
ns.test.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 test. B6HqjRiv3Iy+84ti9nPXkp+ZYikJF7TxpXWd+zpDWJnORxT6+Yy3yfTbikE8s1oMq25L8UzWh1SByBcklzEoag==
a.ns.test.	300	IN	A	2.3.4.5
a.ns.test.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 test. GQ+I6G4Th64EEaSnaFwm1Y1xNJ3TVBUXVEv4XqhulzI0VPe3B+v0wEojp7TEdT17IIZIRRf8IZ5v+7iiPEW9Dw==
a.ns.test.	300	IN	AAAA	bad::cafe
a.ns.test.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 test. 5KqoblqjalCrazgA+/ShmaUrqvRkcA2ZEYeJMLJUQky4MOJep/NHos4FpnwWk7pVGxVYdiSD2I7jqNWQIQDaUA==
a.ns.test.	300	IN	NSEC	test. A AAAA RRSIG NSEC
a.ns.test.	300	IN	NSEC	test. A AAAA CNAME RRSIG NSEC
a.ns.test.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 test. kYCdRpsQfO0n9qi+Gn5aOvWnefz+gmJ6m6Van7AxOxYWrL0BQQnDSSDEdtKDhInkpZrPzKyNYUYXK34Moy52wQ==
`

func TestCheckNSEC(t *testing.T) {
	cases := []struct {
		Zone string
		Result
	}{
		{nsecZone0, Result{0, 0}},
		{nsecZone1, Result{3, 0}},
	}

	viper.Set("verbose", 1)
	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNSEC(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkNSEC expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}
