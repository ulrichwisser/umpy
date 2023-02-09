package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkDS(cache Cache, origin string) (r Result) {
	var labels []string = getLabels(cache)
	for _, label := range labels {
		if _, ok := cache[label]["DS"]; !ok {
			continue
		}
		for _, rr := range cache[label]["DS"] {
			ds := rr.(*dns.DS)
			if !okDigestType(ds.DigestType) {
				log.Errorf("Label %s has DS record with forbidden digest type %s (%d)\n", ds.Header().Name, hash2string(ds.DigestType), ds.DigestType)
				r.errors += 1
			}
			if !okAlgorithm(ds.Algorithm) {
				log.Errorf("Label %s has DS record with forbidden algorithm %s (%d)\n", ds.Header().Name, algorithm2string(ds.Algorithm), ds.Algorithm)
				r.errors += 1
			}
		}
		if _, ok := cache[label]["NS"]; !ok {
			log.Errorf("Label %s has DS record but is not delegated.\n", label)
			r.errors += 1
		}
	}
	return
}
