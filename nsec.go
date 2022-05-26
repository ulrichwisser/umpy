package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkNSEC(cache Cache, origin string) (r Result) {
	var nseclabels []string = getNsecLabels(cache, origin)
	for i := range nseclabels {
		if _, ok := cache[nseclabels[i]]["NSEC"]; !ok {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("Label %s does not have a NSEC record\n", nseclabels[i])
			}
			r.errors += 1
			continue
		}
		if len(cache[nseclabels[i]]["NSEC"]) > 1 {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("Label %s has %d NSEC records, only one expected.\n", nseclabels[i], len(cache[nseclabels[i]]["NSEC"]))
			}
			r.errors += 1
		}
		nsec := cache[nseclabels[i]]["NSEC"][0].(*dns.NSEC)
		nextindex := i + 1
		if nextindex == len(nseclabels) {
			nextindex = 0
		}
		if nsec.NextDomain != nseclabels[nextindex] {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("NSEC record for label %s has %s as next domain. expected %s\n", nseclabels[i], nsec.NextDomain, nseclabels[nextindex])
			}
			r.errors += 1
		}
	}
	return
}
