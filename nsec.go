package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
)

func checkNsec(cache Cache, origin string) (r Result) {
	r.Add(checkNsecChain(cache, origin))
	r.Add(checkNsecNoAdditional(cache, origin))
	r.Add(checkNsecTypeBitmap(cache, origin))
	return
}

func checkNsecChain(cache Cache, origin string) (r Result) {
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

// 	We try to find labels with nsec records that shouldn't have one
func checkNsecNoAdditional(cache Cache, origin string) (r Result) {
	/*
		getNsecLabels and getLabels both return a sorted label list.
	*/
	nseclabels := getNsecLabels(cache, origin)
    labels := getLabels(cache)

	var shouldHaveNsec map[string]bool = make(map[string]bool, 0)
	for _,label := range nseclabels {
		shouldHaveNsec[label] = true
	}

	for _,label := range labels {
		if _, ok := cache[label]["NSEC"]; ok {
			// has NSEC label
			if !shouldHaveNsec[label] {
				log.Errorf("Label %s should not have a NSEC record", label)
				r.errors += 1
				continue
			}
			// has NSEC record as expected
			log.Debugf("Label %s has NSEC record (as expected)", label)
			continue
		} else {
			// has no NSEC label
			if shouldHaveNsec[label] {
				log.Errorf("Label %s should have a NSEC record, but doesn't", label)
				r.errors += 1
				continue
			}
			// has no NSEC record as expected
			log.Debugf("Label %s has no NSEC record (as expected)", label)
			continue

		}
	}
	return
}

// 	We try to find labels with nsec records that shouldn't have one
func checkNsecTypeBitmap(cache Cache, origin string) (r Result) {
	/*
		getNsecLabels and getLAbels both return a sorted label list.
	*/
	nseclabels := getNsecLabels(cache, origin)
	for _,nseclabel := range nseclabels {
		if _, ok := cache[nseclabel]["NSEC"]; !ok {
			log.Errorf("Label %s does not have a NSEC record", nseclabel)
			r.errors += 1
			continue
		}
		nsec := cache[nseclabel]["NSEC"][0].(*dns.NSEC)

		// empty bitmap
		if len(nsec.TypeBitMap)==0 {
			log.Errorf("NSEC record for label %s has an empty bitmap", nseclabel)
			r.errors += 1
			continue
		}

		// compute all types that should be covered
		var typesAtLabel map[uint16]bool = make(map[uint16]bool, 0)
		for typeStr := range cache[nseclabel] {
			for _,rr := range cache[nseclabel][typeStr] {
				typesAtLabel[rr.Header().Rrtype] = true
			}
		}

		// non empty bitmap
		for _,rrtype := range nsec.TypeBitMap {
			if !typesAtLabel[rrtype] {
				log.Errorf("Bitmap for NSEC record %s contains %s (%d), but zone does not contain such a record", nseclabel, dns.TypeToString[rrtype], rrtype)
				r.errors += 1
			}
		}

		// non empty bitmap
		for rrtype := range typesAtLabel {
			var found bool = false
			for _,t := range nsec.TypeBitMap {
				if t == rrtype {
					found = true
					break
				}
			}
			if !found {
				log.Errorf("At label %s zone contains %s (%d) record(s) but is not covered by NSEC", nseclabel, dns.TypeToString[rrtype], rrtype)
				r.errors += 1
			}
		}
	}
	return
}
