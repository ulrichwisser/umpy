package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkDNSKEY(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["DNSKEY"]; !ok {
		if viper.GetInt("verbose") > 0 {
			fmt.Println("No DNSKEY records at apex of ", origin)
		}
		r.errors += 1
		return
	}

	// keys of same alg must have different keytag
	var keytags map[string]bool = make(map[string]bool)
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		alg_keytag := fmt.Sprintf("%d+%d", key.Algorithm, key.KeyTag())
		if _, ok := keytags[alg_keytag]; ok {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("DNSKEY RRset contains two keys of algorithm %s (%d) with KeyTag %d\n", algorithm2string(key.Algorithm), key.Algorithm, key.KeyTag())
			}
			r.warnings += 1
		}
		keytags[alg_keytag] = true
	}

	// at least one key of each algorithm should have the SEP flag set
	var algSEP map[uint8]bool = make(map[uint8]bool)
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		if _,ok:= algSEP[key.Algorithm]; !ok {
			algSEP[key.Algorithm] = false
		}
		if key.Flags & dns.SEP == dns.SEP {
			algSEP[key.Algorithm] = true
		}
	}
	for alg := range algSEP {
		if !algSEP[alg] {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("No DNSKEY of algorithm %s (%d) has SEP flag set\n", algorithm2string(alg), alg)
			}
			r.warnings += 1
		}
	}

	// only allows algorithms used
	for _, k := range cache[origin]["DNSKEY"] {
		var key *dns.DNSKEY = k.(*dns.DNSKEY)
		if !okAlgorithm(key.Algorithm) {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("DNSKEY with algorithm %s (%d) found\n", algorithm2string(key.Algorithm), key.Algorithm)
			}
			r.warnings += 1
		}
	}

	// done
	return
}
