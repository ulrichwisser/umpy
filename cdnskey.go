package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
)

func checkCDNSKEY(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDNSKEY"]; !ok {
		log.Info("No CDNSKEY records found.")
		return
	}

	// CDNSKEY only at apex
	r.Add(checkOnlyAtApex(cache, origin, "CDNSKEY"))

	// CDNSKEY must be signed by KSK
	r.Add(checkSignedBySEP(cache, origin, "CDNSKEY"))
	
	// CDNSKEY all have algorithm zero or none
	r.Add(checkCDNSKEYzero(cache, origin))
	
	// checks if CDNSKEY uses allowed algorithm/flags/protocol
	r.Add(checkCDNSKEYparam(cache, origin))

	// checks if at least one CDNSKEY refers to a DNSKEY record in the DNSKEY RR set that signs the DNSKEY RR set
	r.Add(checkCDNSKEYsignsDNSKEY(cache, origin))

	// done
	return
}

func checkCDNSKEYsignsDNSKEY(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDNSKEY"]; !ok {
		log.Info("NO CDNSKEY records at apex.")
		return
	}
	if _, ok := cache[origin]["DNSKEY"]; !ok {
		log.Error("NO DNSKEY records found! Could not check CDNSKEY record.")
		r.errors++
		return
	}

	// try to find a DNSKEY record for every CDNSKEY record
	keysfound := 0
	for _, rr := range cache[origin]["CDNSKEY"] {
		cdnskey := rr.(*dns.CDNSKEY)
		found := false
		valid := false
		for _, key := range cache[origin]["DNSKEY"] {
			keycdnskey := key.(*dns.DNSKEY).ToCDNSKEY()
			keycdnskey.Header().Ttl = cdnskey.Header().Ttl
			if cdnskey.String() == keycdnskey.String() {
				found = true
				if key.(*dns.DNSKEY).Flags&dns.SEP != dns.SEP {
					log.Warnf("CDNSKEY record with alg=%d and keyTag=%d, refers to DNSKEY that does not have the SEP flag set.", cdnskey.Algorithm, cdnskey.KeyTag())
					r.warnings++
				}
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
				log.Infof("CDNSKEY record with alg=%d and keyTag=%d, refers to DNSKEY that does not sign the DNSKEY RR set.", cdnskey.Algorithm, cdnskey.KeyTag())
			}
		} else {
			log.Warnf("NO DNSKEY record for CDNSKEY record with alg=%d and keyTag=%d found.", cdnskey.Algorithm, cdnskey.KeyTag())
			r.warnings++
		}
	}
	if keysfound == 0 {
		log.Errorf("CDNSKEY RR set is invalid because there are no corrosponding DNSKEY records.")
		r.errors++
	}

	return
}

func checkCDNSKEYzero(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["CDNSKEY"]; !ok {
		log.Debug("NO CDNSKEY records at apex.")
		return
	}

	algZero := 0
	algNonZero := 0
	for _, rr := range cache[origin]["CDNSKEY"] {
		if rr.(*dns.CDNSKEY).Algorithm == 0 {
			algZero++
		} else {
			algNonZero++
		}
	}

	if algZero > 0 && algNonZero > 0 {
		log.Error("CDNSKEY records with algorithm 0 and with other algorithms are found.")
		r.errors += 1
	}
	return
}

func checkCDNSKEYparam(cache Cache, origin string) (r Result) {
	for _, rr := range cache[origin]["CDNSKEY"] {
	    cdnskey := rr.(*dns.CDNSKEY)

		if cdnskey.Algorithm == 0 {
			if cdnskey.Flags != 0 {
				log.Warnf("CDNSKEY records with algorithm 0 should have flags set to zero, found %d", cdnskey.Flags)
				r.warnings += 1
			}
			if cdnskey.Protocol != 3 {
				log.Errorf("CDNSKEY records with algorithm 0 should have protocol set to 3, found %d", cdnskey.Protocol)
				r.errors += 1
			}
			if cdnskey.PublicKey != "AA==" {
				log.Warnf("CDNSKEY records with algorithm 0 should have public key set to 'AA==', found %s", cdnskey.PublicKey)
				r.warnings += 1
			}
		} else {
			if !okAlgorithm(cdnskey.Algorithm) {
				log.Errorf("CDNSKEY record with forbidden algorithm %s (%d)", algorithm2string(cdnskey.Algorithm), cdnskey.Algorithm)
				r.errors += 1
			}
			if cdnskey.Flags != 0 {
				log.Warnf("CDNSKEY records have flags set to zero, found %d", cdnskey.Flags)
				r.warnings += 1
			}
			if cdnskey.Protocol != 3 {
				log.Errorf("CDNSKEY records should have protocol set to 3, found %d", cdnskey.Protocol)
				r.errors += 1
			}
		}
	}
	return
}
