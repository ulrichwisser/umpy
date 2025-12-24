package main

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

var nsecZone0 string = `
neseczone0.	300	IN	SOA	master.ns.neseczone0. mail.nic.neseczone0. 12345 1800 3600 7200 14400
neseczone0.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 neseczone0. WMA4R0HY1Kd9lPAwfnEbFJsvCNXNNGaKd0H1qSuVYh2sHlvHVPXyqKoclEZauYX/P4dEezwW1Ow15LIyJKbNOA==
neseczone0.	300	IN	NS	a.ns.neseczone0.
neseczone0.	300	IN	NS	ns.neseczone0.
neseczone0.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 neseczone0. Bc/kRNMbUO7fWz0zW7EnkCliA18qQhkBBPHwKBqW8DS5mpSqmRQxu12doazex/v4bbR9uoj6BsAN070dcxFq7w==
neseczone0.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
neseczone0.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
neseczone0.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 neseczone0. oySh9y2KXbVtUgIMVwhcSHbYnEKb5zegRh/3DG9wylfI70ptdH+UVDLvujCixgCR3NxxDq5nQsrw9MW+uDLzYA==
neseczone0.	300	IN	NSEC	brokensig.neseczone0. NS SOA RRSIG NSEC DNSKEY
neseczone0.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 neseczone0. m8gEEWBy1qNLHkIwjFm3Z0eXQzh9yiVsK+FLHVD/cVDU3BN06+5AMBiGu9yDUPCq1W1CHyKI+LUU1cWTqk0qlg==
brokensig.neseczone0.	300	IN	A	10.0.0.0
brokensig.neseczone0.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone0. ogZaRb7PxJTtOrpMdw4nYMQaXIX+uz97/hnYBim9WHxLMt+Rj+kjjgKw9edpaeU4fsZCXFtIjggOQVrI2FA+zg==
brokensig.neseczone0.	300	IN	NSEC	domain.neseczone0. A RRSIG NSEC
brokensig.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. JZFWTtPt5SKbVIzdV2TbO/ktX7jQbe0VdgS7FZpJgg2DaBvgUp/s+yfaO29N66OMGQI9Y7vWY8Eh826EtHCepQ==
domain.neseczone0.	300	IN	NS	noglue.example.
domain.neseczone0.	300	IN	NSEC	domain2.neseczone0. NS RRSIG NSEC
domain.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. LtInINyNBeCfIqcf54rC4TvR4xWNajylULWSL8BU/EyY/II1sCrWLorl8XUl/nZFhM5sCEXzqJTm+nRyeR0tnA==
domain2.neseczone0.	300	IN	NS	glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
domain2.neseczone0.	300	IN	NSEC	domain3.neseczone0. NS RRSIG NSEC
domain2.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. d+FhpZA4SVAyGvMadvcuqk2O2LVYzc5/k6VbsKoxpbg82lsYski8ThBpGDs8vKM1UZwdggyIohrUhwFCdd5QxA==
domain3.neseczone0.	300	IN	A	4.5.6.7
domain3.neseczone0.	300	IN	NS	ns.domain3.neseczone0.
domain3.neseczone0.	300	IN	NS	domain3.neseczone0.
domain3.neseczone0.	300	IN	NSEC	domain4.neseczone0. NS RRSIG NSEC
domain3.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. Qyvh8+uA8Y6mdVZGxeY/58E7ZUOmWRQEXXSDw7l6nKwF6ARWxnUxPzXdI4YQf6K8gV0lfnyU1H9e871CdH8+wg==
ns.domain3.neseczone0.	300	IN	AAAA	dead::beef
domain4.neseczone0.	300	IN	TXT	"blahhblahhblahh"
domain4.neseczone0.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 neseczone0. pAmD3Xyn1cJo1TGW/Pgxm9NGO2KtDl6H5TuLSBpD4QhIgE7pvD7KOnqMvbRkN7p/XiF4oIE50aeVOz0yVYt8Sw==
domain4.neseczone0.	300	IN	NSEC	ns.neseczone0. TXT RRSIG NSEC
domain4.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. p4u+q9tj80uohqMY1UWP4hbVS7fe1nJXgkXsQQFNVarfZbKx+pQD5oxCAk/sdYen82rF93rr74ON3wWT8vhrLw==
ns.neseczone0.	300	IN	A	1.2.3.4
ns.neseczone0.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone0. 8susQ9PcknV86vchocRejC8zf77Yacyp7FbLL4neS3K2QKkGDW2k3jUbssAJzLuyddPdjWcdyUgSnnjAhx6EPw==
ns.neseczone0.	300	IN	AAAA	cafe::bad
ns.neseczone0.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 neseczone0. ANXH1JnaHO+dtvOrwRPgeecQmKg4JwYd7Fmpezz00HUC5uHeb5/p38nm+X4SEAe2AyoG94a4sMt4/fZ9exjJ/g==
ns.neseczone0.	300	IN	NSEC	a.ns.neseczone0. A AAAA RRSIG NSEC
ns.neseczone0.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone0. B6HqjRiv3Iy+84ti9nPXkp+ZYikJF7TxpXWd+zpDWJnORxT6+Yy3yfTbikE8s1oMq25L8UzWh1SByBcklzEoag==
a.ns.neseczone0.	300	IN	A	2.3.4.5
a.ns.neseczone0.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 neseczone0. GQ+I6G4Th64EEaSnaFwm1Y1xNJ3TVBUXVEv4XqhulzI0VPe3B+v0wEojp7TEdT17IIZIRRf8IZ5v+7iiPEW9Dw==
a.ns.neseczone0.	300	IN	AAAA	bad::cafe
a.ns.neseczone0.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 neseczone0. 5KqoblqjalCrazgA+/ShmaUrqvRkcA2ZEYeJMLJUQky4MOJep/NHos4FpnwWk7pVGxVYdiSD2I7jqNWQIQDaUA==
a.ns.neseczone0.	300	IN	NSEC	neseczone0. A AAAA RRSIG NSEC
a.ns.neseczone0.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 neseczone0. kYCdRpsQfO0n9qi+Gn5aOvWnefz+gmJ6m6Van7AxOxYWrL0BQQnDSSDEdtKDhInkpZrPzKyNYUYXK34Moy52wQ==
`
var nsecZone1 string = `
neseczone1.	300	IN	SOA	master.ns.neseczone1. mail.nic.neseczone1. 12345 1800 3600 7200 14400
neseczone1.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 neseczone1. WMA4R0HY1Kd9lPAwfnEbFJsvCNXNNGaKd0H1qSuVYh2sHlvHVPXyqKoclEZauYX/P4dEezwW1Ow15LIyJKbNOA==
neseczone1.	300	IN	NS	a.ns.neseczone1.
neseczone1.	300	IN	NS	ns.neseczone1.
neseczone1.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 neseczone1. Bc/kRNMbUO7fWz0zW7EnkCliA18qQhkBBPHwKBqW8DS5mpSqmRQxu12doazex/v4bbR9uoj6BsAN070dcxFq7w==
neseczone1.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
neseczone1.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
neseczone1.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 neseczone1. oySh9y2KXbVtUgIMVwhcSHbYnEKb5zegRh/3DG9wylfI70ptdH+UVDLvujCixgCR3NxxDq5nQsrw9MW+uDLzYA==
neseczone1.	300	IN	NSEC	brokensig.neseczone1. NS SOA RRSIG NSEC DNSKEY
neseczone1.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 neseczone1. m8gEEWBy1qNLHkIwjFm3Z0eXQzh9yiVsK+FLHVD/cVDU3BN06+5AMBiGu9yDUPCq1W1CHyKI+LUU1cWTqk0qlg==
brokensig.neseczone1.	300	IN	A	10.0.0.0
brokensig.neseczone1.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone1. ogZaRb7PxJTtOrpMdw4nYMQaXIX+uz97/hnYBim9WHxLMt+Rj+kjjgKw9edpaeU4fsZCXFtIjggOQVrI2FA+zg==
brokensig.neseczone1.	300	IN	NSEC	domain.neseczone1. A RRSIG NSEC
brokensig.neseczone1.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone1. JZFWTtPt5SKbVIzdV2TbO/ktX7jQbe0VdgS7FZpJgg2DaBvgUp/s+yfaO29N66OMGQI9Y7vWY8Eh826EtHCepQ==
domain.neseczone1.	300	IN	NS	noglue.example.
domain.neseczone1.	300	IN	NSEC	domain2.neseczone1. NS RRSIG NSEC
domain.neseczone1.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone1. LtInINyNBeCfIqcf54rC4TvR4xWNajylULWSL8BU/EyY/II1sCrWLorl8XUl/nZFhM5sCEXzqJTm+nRyeR0tnA==
domain2.neseczone1.	300	IN	NS	glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
domain2.neseczone1.	300	IN	NSEC	domain3.neseczone1. NS RRSIG NSEC
domain2.neseczone1.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone1. d+FhpZA4SVAyGvMadvcuqk2O2LVYzc5/k6VbsKoxpbg82lsYski8ThBpGDs8vKM1UZwdggyIohrUhwFCdd5QxA==
domain3.neseczone1.	300	IN	A	4.5.6.7
domain3.neseczone1.	300	IN	NS	ns.domain3.neseczone1.
domain3.neseczone1.	300	IN	NS	domain3.neseczone1.
domain3.neseczone1.	300	IN	NSEC	ns.neseczone1. NS RRSIG NSEC
domain3.neseczone1.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone1. Qyvh8+uA8Y6mdVZGxeY/58E7ZUOmWRQEXXSDw7l6nKwF6ARWxnUxPzXdI4YQf6K8gV0lfnyU1H9e871CdH8+wg==
ns.domain3.neseczone1.	300	IN	AAAA	dead::beef
domain4.neseczone1.	300	IN	TXT	"blahhblahhblahh"
domain4.neseczone1.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 neseczone1. pAmD3Xyn1cJo1TGW/Pgxm9NGO2KtDl6H5TuLSBpD4QhIgE7pvD7KOnqMvbRkN7p/XiF4oIE50aeVOz0yVYt8Sw==
ns.neseczone1.	300	IN	A	1.2.3.4
ns.neseczone1.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone1. 8susQ9PcknV86vchocRejC8zf77Yacyp7FbLL4neS3K2QKkGDW2k3jUbssAJzLuyddPdjWcdyUgSnnjAhx6EPw==
ns.neseczone1.	300	IN	AAAA	cafe::bad
ns.neseczone1.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 neseczone1. ANXH1JnaHO+dtvOrwRPgeecQmKg4JwYd7Fmpezz00HUC5uHeb5/p38nm+X4SEAe2AyoG94a4sMt4/fZ9exjJ/g==
ns.neseczone1.	300	IN	NSEC	a.ns.neseczone1. A AAAA RRSIG NSEC
ns.neseczone1.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone1. B6HqjRiv3Iy+84ti9nPXkp+ZYikJF7TxpXWd+zpDWJnORxT6+Yy3yfTbikE8s1oMq25L8UzWh1SByBcklzEoag==
a.ns.neseczone1.	300	IN	A	2.3.4.5
a.ns.neseczone1.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 neseczone1. GQ+I6G4Th64EEaSnaFwm1Y1xNJ3TVBUXVEv4XqhulzI0VPe3B+v0wEojp7TEdT17IIZIRRf8IZ5v+7iiPEW9Dw==
a.ns.neseczone1.	300	IN	AAAA	bad::cafe
a.ns.neseczone1.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 neseczone1. 5KqoblqjalCrazgA+/ShmaUrqvRkcA2ZEYeJMLJUQky4MOJep/NHos4FpnwWk7pVGxVYdiSD2I7jqNWQIQDaUA==
a.ns.neseczone1.	300	IN	NSEC	neseczone1. A AAAA RRSIG NSEC
a.ns.neseczone1.	300	IN	NSEC	neseczone1. A AAAA CNAME RRSIG NSEC
a.ns.neseczone1.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 neseczone1. kYCdRpsQfO0n9qi+Gn5aOvWnefz+gmJ6m6Van7AxOxYWrL0BQQnDSSDEdtKDhInkpZrPzKyNYUYXK34Moy52wQ==
`
var nsecZone2 string = `
neseczone2.	300	IN	SOA	master.ns.neseczone2. mail.nic.neseczone2. 12345 1800 3600 7200 14400
neseczone2.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 neseczone2. WMA4R0HY1Kd9lPAwfnEbFJsvCNXNNGaKd0H1qSuVYh2sHlvHVPXyqKoclEZauYX/P4dEezwW1Ow15LIyJKbNOA==
neseczone2.	300	IN	NS	a.ns.neseczone2.
neseczone2.	300	IN	NS	ns.neseczone2.
neseczone2.	300	IN	RRSIG	NS 13 1 300 20220130235959 20220101000000 11082 neseczone2. Bc/kRNMbUO7fWz0zW7EnkCliA18qQhkBBPHwKBqW8DS5mpSqmRQxu12doazex/v4bbR9uoj6BsAN070dcxFq7w==
neseczone2.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
neseczone2.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
neseczone2.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 neseczone2. oySh9y2KXbVtUgIMVwhcSHbYnEKb5zegRh/3DG9wylfI70ptdH+UVDLvujCixgCR3NxxDq5nQsrw9MW+uDLzYA==
neseczone2.	300	IN	NSEC	brokensig.neseczone2. NS SOA RRSIG NSEC DNSKEY
neseczone2.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 neseczone2. m8gEEWBy1qNLHkIwjFm3Z0eXQzh9yiVsK+FLHVD/cVDU3BN06+5AMBiGu9yDUPCq1W1CHyKI+LUU1cWTqk0qlg==
brokensig.neseczone2.	300	IN	A	10.0.0.0
brokensig.neseczone2.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone2. ogZaRb7PxJTtOrpMdw4nYMQaXIX+uz97/hnYBim9WHxLMt+Rj+kjjgKw9edpaeU4fsZCXFtIjggOQVrI2FA+zg==
brokensig.neseczone2.	300	IN	NSEC	domain.neseczone2. A RRSIG NSEC
brokensig.neseczone2.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone2. JZFWTtPt5SKbVIzdV2TbO/ktX7jQbe0VdgS7FZpJgg2DaBvgUp/s+yfaO29N66OMGQI9Y7vWY8Eh826EtHCepQ==
domain.neseczone2.	300	IN	NS	noglue.example.
domain.neseczone2.	300	IN	NSEC	domain2.neseczone2. NS RRSIG NSEC
domain.neseczone2.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone2. LtInINyNBeCfIqcf54rC4TvR4xWNajylULWSL8BU/EyY/II1sCrWLorl8XUl/nZFhM5sCEXzqJTm+nRyeR0tnA==
domain2.neseczone2.	300	IN	NS	glue.example.
glue.example. 300 IN A 3.4.5.6
glue.example. 300 IN AAAA aced::cafe
glue.example.	300	IN	NSEC	domain2.neseczone2. A AAAA NSEC
domain2.neseczone2.	300	IN	NSEC	domain3.neseczone2. NS RRSIG NSEC
domain2.neseczone2.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone2. d+FhpZA4SVAyGvMadvcuqk2O2LVYzc5/k6VbsKoxpbg82lsYski8ThBpGDs8vKM1UZwdggyIohrUhwFCdd5QxA==
domain3.neseczone2.	300	IN	A	4.5.6.7
domain3.neseczone2.	300	IN	NS	ns.domain3.neseczone2.
domain3.neseczone2.	300	IN	NS	domain3.neseczone2.
domain3.neseczone2.	300	IN	NSEC	ns.neseczone2. NS RRSIG NSEC
domain3.neseczone2.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone2. Qyvh8+uA8Y6mdVZGxeY/58E7ZUOmWRQEXXSDw7l6nKwF6ARWxnUxPzXdI4YQf6K8gV0lfnyU1H9e871CdH8+wg==
ns.domain3.neseczone2.	300	IN	AAAA	dead::beef
domain4.neseczone2.	300	IN	TXT	"blahhblahhblahh"
domain4.neseczone2.	300	IN	RRSIG	TXT 13 2 300 20220130235959 20220101000000 11082 neseczone2. pAmD3Xyn1cJo1TGW/Pgxm9NGO2KtDl6H5TuLSBpD4QhIgE7pvD7KOnqMvbRkN7p/XiF4oIE50aeVOz0yVYt8Sw==
empty.neseczone2. 300 TXT "This is a text"
empty.neseczone2.	300	IN	NSEC	ns.neseczone2.  
ns.neseczone2.	300	IN	A	1.2.3.4
ns.neseczone2.	300	IN	RRSIG	A 13 2 300 20220130235959 20220101000000 11082 neseczone2. 8susQ9PcknV86vchocRejC8zf77Yacyp7FbLL4neS3K2QKkGDW2k3jUbssAJzLuyddPdjWcdyUgSnnjAhx6EPw==
ns.neseczone2.	300	IN	AAAA	cafe::bad
ns.neseczone2.	300	IN	RRSIG	AAAA 13 2 300 20220130235959 20220101000000 11082 neseczone2. ANXH1JnaHO+dtvOrwRPgeecQmKg4JwYd7Fmpezz00HUC5uHeb5/p38nm+X4SEAe2AyoG94a4sMt4/fZ9exjJ/g==
ns.neseczone2.	300	IN	NSEC	a.ns.neseczone2. A AAAA RRSIG NSEC CNAME RRSIG HINFO NS MX TXT 
ns.neseczone2.	300	IN	RRSIG	NSEC 13 2 300 20220130235959 20220101000000 11082 neseczone2. B6HqjRiv3Iy+84ti9nPXkp+ZYikJF7TxpXWd+zpDWJnORxT6+Yy3yfTbikE8s1oMq25L8UzWh1SByBcklzEoag==
a.ns.neseczone2.	300	IN	A	2.3.4.5
a.ns.neseczone2.  300 IN  TXT "Help"
a.ns.neseczone2.	300	IN	RRSIG	A 13 3 300 20220130235959 20220101000000 11082 neseczone2. GQ+I6G4Th64EEaSnaFwm1Y1xNJ3TVBUXVEv4XqhulzI0VPe3B+v0wEojp7TEdT17IIZIRRf8IZ5v+7iiPEW9Dw==
a.ns.neseczone2.	300	IN	AAAA	bad::cafe
a.ns.neseczone2.	300	IN	RRSIG	AAAA 13 3 300 20220130235959 20220101000000 11082 neseczone2. 5KqoblqjalCrazgA+/ShmaUrqvRkcA2ZEYeJMLJUQky4MOJep/NHos4FpnwWk7pVGxVYdiSD2I7jqNWQIQDaUA==
a.ns.neseczone2.	300	IN	NSEC	neseczone2. A AAAA RRSIG NSEC
a.ns.neseczone2.	300	IN	NSEC	neseczone2. A AAAA NSEC
a.ns.neseczone2.	300	IN	RRSIG	NSEC 13 3 300 20220130235959 20220101000000 11082 neseczone2. kYCdRpsQfO0n9qi+Gn5aOvWnefz+gmJ6m6Van7AxOxYWrL0BQQnDSSDEdtKDhInkpZrPzKyNYUYXK34Moy52wQ==
`

func TestCheckNsec(t *testing.T) {
	cases := []struct {
		Zone string
		Result
	}{
		{nsecZone0, Result{0, 0}},
		{nsecZone1, Result{5, 0}},
		{nsecZone2, Result{6, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNSEC(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkNSEC expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}

func TestCheckNsecChain(t *testing.T) {
	cases := []struct {
		Zone string
		Result
	}{
		{nsecZone0, Result{0, 0}},
		{nsecZone1, Result{3, 0}},
		{nsecZone2, Result{3, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNsecChain(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkNsecChain expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}

func TestCheckNsecNoAdditional(t *testing.T) {
	cases := []struct {
		Zone string
		Result
	}{
		{nsecZone0, Result{0, 0}},
		{nsecZone1, Result{2, 0}},
		{nsecZone2, Result{3, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNoAdditionalNsec(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkNoAdditionalNsec expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}

func TestCheckNsecTypeBitmap(t *testing.T) {
	cases := []struct {
		Zone string
		Result
	}{
		//{nsecZone0, Result{0, 0}},
		//{nsecZone1, Result{2, 0}},
		{nsecZone2, Result{3, 0}},
	}

	viper.Set("verbose", 4)

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNsecTypeBitmap(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkNsecTypeBitmap expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}
