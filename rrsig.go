package main

import (
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkRRSIG(cache Cache, origin string) (r Result) {
	labels := getLabels(cache)

	// now is the date and time used as reference for signature validation
	var now uint32
	if viper.IsSet("now") {
		t, err := time.Parse(time.RFC3339, viper.GetString("now"))
		if err != nil {
			log.Errorf("Error decoding timestamp '%s' %s\n", viper.GetString("now"), err)
			r.errors = 1
			return
		}
		now = uint32(t.Unix())
	} else {
		now = uint32(time.Now().Unix())
	}

	// compute timing boundaries
	minage := now - uint32(viper.GetInt(MINAGE))
	maxage := now - uint32(viper.GetInt(MAXAGE))
	minvalid := now + uint32(viper.GetInt(MINVALID))
	maxvalid := now + uint32(viper.GetInt(MAXVALID))
	log.Infof("Reference time NOW      is %s (%d)", time.Unix(int64(now), 0).UTC(), now)
	log.Infof("Reference time MINAGE   is %s (%d)", time.Unix(int64(minage), 0).UTC(), minage)
	log.Infof("Reference time MAXAGE   is %s (%d)", time.Unix(int64(maxage), 0).UTC(), maxage)
	log.Infof("Reference time MINVALID is %s (%d)", time.Unix(int64(minvalid), 0).UTC(), minvalid)
	log.Infof("Reference time MAXVALID is %s (%d)", time.Unix(int64(maxvalid), 0).UTC(), maxvalid)

	// start checking all labels
	for _, label := range labels {
		for rrtype := range cache[label] {
			if strings.HasPrefix(rrtype, "RRSIG") {
				continue
			}

			if isDelegated(label, cache, origin) {
				// label is delegated, no signatures should exist, except DS and NSEC
				if rrtype != "DS" && rrtype != "NSEC" && rrtype != "NSEC3" {
					if _, ok := cache[label]["RRSIG"+rrtype]; ok {
						log.Errorf("Label %s is delegated, but RR type %s is signed.\n", label, rrtype)
						r.errors++
						continue
					}
					// this is good, no signature exists, so nothing to do
					continue
				}
			}

			// check existence of signatures
			if _, ok := cache[label]["RRSIG"+rrtype]; !ok || len(cache[label]["RRSIG"+rrtype]) == 0 {
				log.Errorf("No signature for label %s rrtype %s\n", label, rrtype)
				r.errors++
				continue
			}

			// check timing
			for _, rr := range cache[label]["RRSIG"+rrtype] {
				r.Add(checkRRSIGTiming(rr.(*dns.RRSIG), minage, maxage, minvalid, maxvalid))
			}

			// validate signatures
			r.Add(checkSig(cache[origin]["DNSKEY"], cache[label][rrtype], cache[label]["RRSIG"+rrtype]))
		}

	}
	return
}

func checkRRSIGTiming(rrsig *dns.RRSIG, minage, maxage, minvalid, maxvalid uint32) (r Result) {
	if rrsig.Inception > minage {
		log.Errorf("Signature for %s %s is too new. Inception is %s, max allowed %s", rrsig.Header().Name, dns.TypeToString[rrsig.TypeCovered], dns.TimeToString(rrsig.Inception), dns.TimeToString(minage))
		r.errors += 1
	}
	if rrsig.Inception < maxage {
		log.Errorf("Signature for %s %s is too old. Inception is %s, min allowed %s", rrsig.Header().Name, dns.TypeToString[rrsig.TypeCovered], dns.TimeToString(rrsig.Inception), dns.TimeToString(maxage))
		r.errors += 1
	}
	if rrsig.Expiration < minvalid {
		log.Errorf("Signature for %s %s expires too soon. Expiration is %s, min allowed %s.", rrsig.Header().Name, dns.TypeToString[rrsig.TypeCovered], dns.TimeToString(rrsig.Expiration), dns.TimeToString(minvalid))
		r.errors += 1
	}
	if rrsig.Expiration > maxvalid {
		log.Errorf("Signature for %s %s expires too late. Expiration is %s, max allowed %s.", rrsig.Header().Name, dns.TypeToString[rrsig.TypeCovered], dns.TimeToString(rrsig.Expiration), dns.TimeToString(maxvalid))
		r.errors += 1
	}
	return
}

func checkSig(keys []dns.RR, rrset []dns.RR, rrsigs []dns.RR) (r Result) {

	// Check parameters
	if !dns.IsRRset(keys) || keys[0].Header().Rrtype != dns.TypeDNSKEY {
		log.Errorf("First parameter is not a DNSKEY set")
		r.errors++
		return
	}
	if !dns.IsRRset(rrset) {
		log.Errorf("Second parameter is not a RR set")
		r.errors++
		return
	}
	if !dns.IsRRset(rrsigs) || rrsigs[0].Header().Rrtype != dns.TypeRRSIG {
		log.Errorf("Third parameter is not a RRSIG set")
		r.errors++
		return
	}
	if rrsigs[0].(*dns.RRSIG).TypeCovered != rrset[0].Header().Rrtype {
		log.Errorf("RRSIG set does not cover RR set.")
		r.errors++
		return
	}

	// now check the signature
	for _, rrsig := range rrsigs {
		valid := false
		for _, key := range keys {
			err := rrsig.(*dns.RRSIG).Verify(key.(*dns.DNSKEY), rrset)
			if err == nil {
				valid = true
				break
			}
		}
		if !valid {
			log.Errorf("RRSIG for %s %s keyTag %d did not validate", rrsig.Header().Name, dns.TypeToString[rrsig.(*dns.RRSIG).TypeCovered], rrsig.(*dns.RRSIG).KeyTag)
			r.errors++
		}
	}

	return
}
