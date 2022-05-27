package main

import (
	"strings"
	"testing"

	//"github.com/spf13/viper"
	"github.com/miekg/dns"
)

var dnskeyZone0 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
`
var dnskeyZone1 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
`
var dnskeyZone2 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	DNSKEY  257 3 13 +s9JyBVaDVllZjVM1sgpXZxjo13cz/KHiYfQ0P14BaUYcy8/L8b57AU3AoZ0/Ken5lG+ZO9biPC8Ek+XVn55BQ== ;{id = 185 (ksk), size = 256b}
test.	300	IN	DNSKEY  257 3 13 muZog6Q/E0r76zzPY7sN6hlE/LyKwaw/ymjhlBUbN6pTjm0DlQ5YkxjhliihD8wGJ0Jc35y0ETzDZSMEyA6msg== ;{id = 185 (ksk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
`

var dnskeyZone3 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	DNSKEY	256 3 8 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
`

var dnskeyZone4 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	DNSKEY	256 3 27 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
`

func TestCheckDNSKEY(t *testing.T) {
	cases := []struct {
		Zone     string
		Expected Result
	}{
		{dnskeyZone0, Result{1,0}},
		{dnskeyZone1, Result{0,0}},
		{dnskeyZone2, Result{0,4}},
		{dnskeyZone3, Result{0,2}},
		{dnskeyZone4, Result{0,3}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkDNSKEY(cache, origin); r != c.Expected {
			t.Logf("Test case %d: checkDNSKEY expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.Expected.errors, c.Expected.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}

var signsKeyZone0 string = `
test.	300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.	300	IN	RRSIG	SOA 13 1 300 20220130235959 20220101000000 11082 test. b1ACEv+pTeBYgeQ7ZZxloV7qssb8a17azszTfxoRB0NbqnI+x4uD9BgTFGnp2tpo1TykmRGiUtNSAHk5EqFUPg==
test.	300	IN	NS	a.ns.test.
test.	300	IN	NS	ns.test.
test.	300	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA== ;{id = 32290 (ksk), size = 256b}
test.	300	IN	DNSKEY	256 3 27 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw== ;{id = 11082 (zsk), size = 256b}
test.	300	IN	RRSIG	DNSKEY 13 1 300 20220130235959 20220101000000 32290 test. Y5B9IvpOrLsWk9UBTv8IJXhYHH2cZ6xzoW1mGBHXisjyh5AnCvaTRQD75kwe96zaH42ZNeqVdUi9CQ29qjH0/g==
test.	300	IN	NSEC	brokensig.test. NS SOA RRSIG NSEC DNSKEY
test.	300	IN	RRSIG	NSEC 13 1 300 20220130235959 20220101000000 11082 test. ggcZp9vWnRPcX2noMta0dPv4KjsYTugO2ODW3jaBacf5QQfz3DYq/KIZprqsTZf2DThXKmQV+qRsUY4hcrNbJw==
brokensig.test.	300	IN	A	10.0.0.0
`

func TestSignsKey(t *testing.T) {
		myReader := strings.NewReader(signsKeyZone0)
		origin, cache := readZonefile(myReader)

		// 2nd parameter not rr set
		myset := append(cache[origin]["NS"], cache[origin]["SOA"][0])
		_, err := keySigns(cache[origin]["DNSKEY"][0].(*dns.DNSKEY), myset, cache[origin]["RRSIGDNSKEY"])
		if err == nil {
			t.Log("Test case 0: signsKey expected errors, got none")
			t.Fail()
		}

		// 3rd parameter not rr set
		_, err = keySigns(cache[origin]["DNSKEY"][0].(*dns.DNSKEY), cache[origin]["NS"], cache[origin]["NS"])
		if err == nil {
			t.Log("Test case 1: signsKey expected errors, got none")
			t.Fail()
		}

		// not type covered
		_, err = keySigns(cache[origin]["DNSKEY"][0].(*dns.DNSKEY), cache[origin]["NS"],cache[origin]["RRSIGDNSKEY"])
		if err == nil {
			t.Log("Test case 2: signsKey expected errors, got none")
			t.Fail()
		}
}
