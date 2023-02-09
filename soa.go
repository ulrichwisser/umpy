package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkSOA(cache Cache, origin string) (r Result) {
	soa, ok := cache[origin]["SOA"][0].(*dns.SOA)
	if !ok {
		log.Error("No SOA record found.")
		r.errors = 1
		return
	}

	// compute timing boundaries
	minvalid := uint32(viper.GetInt(MINVALID))

	if soa.Expire >= minvalid {
		log.Errorf("SOA Expire %d is too long. Must be less then %s %d", soa.Expire, MINVALID, minvalid)
		r.errors = 1
	}
	return
}
