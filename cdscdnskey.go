package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
)

// checks that CDS and CDNSKEY point to the same keys or both use algorithm zero
func checkCDSCDNSKEY(cache Cache, origin string) (r Result) {

	if _, ok := cache[origin]["CDS"]; !ok {
		log.Debug("NO CDS records at apex.")
		return
	}
	if _, ok := cache[origin]["CDNSKEY"]; !ok {
		log.Debug("NO CDNSKEY records at apex.")
		return
	}

    for _,rr := range cache[origin]["CDNSKEY"] {
		cdnskey := rr.(*dns.CDNSKEY)
		found := false
		for _,rc := range cache[origin]["CDS"] {
			cds := rc.(*dns.CDS)
			if cds.Algorithm != cdnskey.Algorithm {
				continue
			}
			if cds.KeyTag != cdnskey.KeyTag() {
				continue
			}
			found = true
		}
		if !found {
			log.Errorf("CDNSKEY record with alg=%d and keytag=%d, had no matching CDS record", cdnskey.Algorithm, cdnskey.KeyTag())
			r.errors++
		}
	}

	for _,rc := range cache[origin]["CDS"] {
		cds := rc.(*dns.CDS)
		found := false
		for _,rr := range cache[origin]["CDNSKEY"] {
			cdnskey := rr.(*dns.CDNSKEY)
			cds := rc.(*dns.CDS)
			if cds.Algorithm != cdnskey.Algorithm {
				continue
			}
			if cds.KeyTag != cdnskey.KeyTag() {
				continue
			}
			found = true
		}
		if !found {
			log.Errorf("CDS record with alg=%d and keytag=%d, had no matching CDNSKEY record", cds.Algorithm, cds.KeyTag)
			r.errors++
		}
	}

	return
}
