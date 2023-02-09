package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
)

func checkNSEC(cache Cache, origin string) (r Result) {
	var nseclabels []string = getNsecLabels(cache, origin)
	for i := range nseclabels {
		if _, ok := cache[nseclabels[i]]["NSEC"]; !ok {
			log.Errorf("Label %s does not have a NSEC record", nseclabels[i])
			r.errors += 1
			continue
		}
		if len(cache[nseclabels[i]]["NSEC"]) > 1 {
			log.Errorf("Label %s has %d NSEC records, only one expected.", nseclabels[i], len(cache[nseclabels[i]]["NSEC"]))
			r.errors += 1
		}
		nsec := cache[nseclabels[i]]["NSEC"][0].(*dns.NSEC)
		nextindex := i + 1
		if nextindex == len(nseclabels) {
			nextindex = 0
		}
		if nsec.NextDomain != nseclabels[nextindex] {
			log.Errorf("NSEC record for label %s has %s as next domain. expected %s", nseclabels[i], nsec.NextDomain, nseclabels[nextindex])
			r.errors += 1
		}
	}
	return
}
