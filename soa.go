package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkSOA(cache Cache, origin string) (r Result) {
	soa, ok := cache[origin]["SOA"][0].(*dns.SOA)
	if !ok {
		if viper.GetInt(VERBOSE) >= VERBOSE_ERROR {
			fmt.Printf("No SOA record found.\n")
		}
		r.errors = 1
		return
	}

	// compute timing boundaries
	minvalid := uint32(viper.GetInt(MINVALID))

	if soa.Expire >= minvalid {
		if viper.GetInt(VERBOSE) >= VERBOSE_ERROR {
			fmt.Printf("SOA Expire %d is too long. Must be less then %s %d\n", soa.Expire, MINVALID, minvalid)
		}
		r.errors = 1
	}
	return
}
