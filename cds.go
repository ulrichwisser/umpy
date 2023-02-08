package main

import (
	"github.com/apex/log"

	"github.com/miekg/dns"
)

func checkCDS(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDS"]; !ok {
		log.Debug("NO CDS records at apex.")
		return
	}

	// CDS only at apex
	r.Add(checkOnlyAtApex(cache, origin, "CDS"))

	// CDS must be signed by KSK
	r.Add(checkSignedBySEP(cache, origin, "CDS"))

	// CDS all have algorithm zero or none
	r.Add(checkCDSzero(cache, origin))

	// The following tests make no sense if CDS uses algorithm 0
	if cdsUsesAlgZero(cache, origin) {
		return
	}

	for _, rr := range cache[origin]["CDS"] {
		cds := rr.(*dns.CDS)

		if !okDigestType(cds.DigestType) {
			log.Errorf("Label %s has CDS record with forbidden digest type %s (%d)", cds.Header().Name, hash2string(cds.DigestType), cds.DigestType)
			r.errors += 1
		}

		if !okAlgorithm(cds.Algorithm) {
			log.Errorf("Label %s has CDS record with forbidden algorithm %s (%d)", cds.Header().Name, algorithm2string(cds.Algorithm), cds.Algorithm)
			r.errors += 1
		}
	}

	// checks if at least one CDS refers to a DNSKEY record in the DNSKEY RR set that signs the DNSKEY RR set
	r.Add(checkCDSsignsDNSKEY(cache, origin))

	return
}

func checkCDSsignsDNSKEY(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDS"]; !ok {
		log.Debug("NO CDS records at apex.")
		return
	}
	if _, ok := cache[origin]["DNSKEY"]; !ok {
		log.Error("NO DNSKEY records found! Could not check CDS record.")
		r.errors++
		return
	}

	// try to find a DNSKEY record for every CDS record
	keysfound := 0
	for _, rr := range cache[origin]["CDS"] {
		cds := rr.(*dns.CDS)
		found := false
		valid := false
		for _, key := range cache[origin]["DNSKEY"] {
			if cds.String() == key.(*dns.DNSKEY).ToDS(cds.DigestType).ToCDS().String() {
				found = true
				// now check the signature
				for _, rrsig := range cache[origin]["RRSIGDNSKEY"] {
					err := rrsig.(*dns.RRSIG).Verify(key.(*dns.DNSKEY), cache[origin]["DNSKEY"])
			        if err == nil {
						valid = true
						break
					} 
				}
		        if valid {
					break
				} 
			}
		}
		if found {
			if valid {
				keysfound++
			} else {
				log.Infof("CDS record with alg=%d and keyTag=%d, refers to DNSKEY that does not sign the DNSKEY RR set.", cds.Algorithm, cds.KeyTag)
			}
		} else {
			log.Warnf("NO DNSKEY record for CDS record with alg=%d and keyTag=%d found.", cds.Algorithm, cds.KeyTag)
			r.warnings++
		}
	}
	if keysfound == 0 {
		log.Errorf("CDS RR set is invalid because there are no corrosponding DNSKEY records.")
		r.errors++
	}

	return
}

func checkCDSzero(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDS"]; !ok {
		log.Debug("NO CDS records at apex.")
		return
	}

	algZero := 0
	algNonZero := 0
	for _, rr := range cache[origin]["CDS"] {
		if rr.(*dns.CDS).Algorithm == 0 {
			algZero++
			r.Add(checkCDSdelete(rr.(*dns.CDS)))
		} else {
			algNonZero++
		}
	}

	if algZero > 0 && algNonZero > 0 {
		log.Error("CDS records with algorithm 0 and with other algorithms are found.")
		r.errors += 1
	}
	return
}

func checkCDSdelete(cds *dns.CDS) (r Result) {
	if cds == nil {
		return
	}
	if cds.Algorithm != 0 {
		return
	}

	if cds.KeyTag != 0 {
		log.Warnf("CDS records with algorithm 0 should have keyTag set to zero, found %d", cds.KeyTag)
		r.warnings += 1
	}
	if cds.DigestType != 0 {
		log.Warnf("CDS records with algorithm 0 should have digest type set to zero, found %d", cds.DigestType)
		r.warnings += 1
	}
	if cds.Digest != "00" {
		log.Warnf("CDS records with algorithm 0 should have digest set to '00', found %s", cds.Digest)
		r.warnings += 1
	}
	return
}

func cdsUsesAlgZero(cache Cache, origin string) bool {
	for _, rr := range cache[origin]["CDS"] {
		if rr.(*dns.CDS).Algorithm == 0 {
			return true
		}
	}
	return false
}
