package main

import (
	"errors"
	"fmt"
	
	"github.com/miekg/dns"

	"github.com/apex/log"
)

func checkDNSKEY(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["DNSKEY"]; !ok {
		log.Errorf("No DNSKEY records at apex of %s", origin)
		r.errors++
		return
	}

	// keys of same alg must have different keytag
	var keytags map[string]bool = make(map[string]bool)
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		alg_keytag := fmt.Sprintf("%d+%d", key.Algorithm, key.KeyTag())
		if _, ok := keytags[alg_keytag]; ok {
			log.Warnf("DNSKEY RRset contains two keys of algorithm %s (%d) with KeyTag %d\n", algorithm2string(key.Algorithm), key.Algorithm, key.KeyTag())
			r.warnings++
		}
		keytags[alg_keytag] = true
	}

	// at least one key of each algorithm should have the SEP flag set
	var algSEP map[uint8]bool = make(map[uint8]bool)
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		if _, ok := algSEP[key.Algorithm]; !ok {
			algSEP[key.Algorithm] = false
		}
		if key.Flags&dns.SEP == dns.SEP {
			algSEP[key.Algorithm] = true
		}
	}
	for alg := range algSEP {
		if !algSEP[alg] {
			log.Warnf("No DNSKEY of algorithm %s (%d) has SEP flag set\n", algorithm2string(alg), alg)
			r.warnings++
		}
	}

	// only allows algorithms used
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		if !okAlgorithm(key.Algorithm) {
			log.Warnf("DNSKEY with algorithm %s (%d) found\n", algorithm2string(key.Algorithm), key.Algorithm)
			r.warnings++
		}
	}

	// check that all keys with SEP flag set sign the DNSKEY set
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		if key.Flags&dns.SEP != dns.SEP {
			continue
		}
		// SEP is set, key must sign DNSKEY set
		signs, err := keySigns(key, cache[origin]["DNSKEY"], cache[origin]["RRSIGDNSKEY"])
		if err != nil {
			log.Error(err.Error())
			r.errors++
		} else if !signs {
			log.Warnf("DNSKEY algorithm %s (%d) keyTag %d, has SEP flag set, but doesn ot sign the DNSKEY set.\n", algorithm2string(key.Algorithm), key.Algorithm, key.KeyTag())
			r.warnings++
		}
	}

	// done
	return
}

func keySigns(key *dns.DNSKEY, rrset []dns.RR, rrsigs []dns.RR) (bool, error) {

	if !dns.IsRRset(rrset) {
		return false, errors.New("Second parameter is not a RR set.")
	}
	if !dns.IsRRset(rrsigs) || rrsigs[0].Header().Rrtype != dns.TypeRRSIG {
		return false, errors.New("Third parameter is not a RRSIG set.")
	}
	if rrsigs[0].(*dns.RRSIG).TypeCovered != rrset[0].Header().Rrtype {
		return false, errors.New("RRSIG set does not cover RR set.")
	}

	// now check the signature
	for _, rrsig := range rrsigs {
		err := rrsig.(*dns.RRSIG).Verify(key, rrset)
		if err == nil {
			return true, nil
		}
	}

	return false, nil
}
