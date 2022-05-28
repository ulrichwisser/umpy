package main

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

/*
$ORIGIN	600	IN SOA	<primary> <mail> (
					1410271268 ; serial
					7200       ; refresh (2 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					600        ; minimum (10 minutes)
					)
*/

func ttl2int(str string) uint32 {
	value, _ := stringToTTL(str)
	return value
}

func TestCheckSOA(t *testing.T) {

	origin, cache := readZonefile(strings.NewReader("example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600"))

	cases := []struct {
		Minvalid uint32
		Result
	}{
		{ttl2int("10d"), Result{1, 0}},
		{ttl2int("13d"), Result{1, 0}},
		{ttl2int("13d23h"), Result{1, 0}},
		{ttl2int("13d23h59m"), Result{1, 0}},
		{ttl2int("14d"), Result{1, 0}},
		{ttl2int("14d1s"), Result{0, 0}},
		{ttl2int("21d"), Result{0, 0}},
	}

	for i, c := range cases {
		viper.Set(MINVALID, c.Minvalid)
		if r := checkSOA(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkSOA expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
	viper.Reset()
}
