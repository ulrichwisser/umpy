package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func readZonefile(zonef io.Reader) (origin string, cache Cache) {
	cache = make(Cache, 0)

	//
	zp := dns.NewZoneParser(zonef, "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Rrtype == dns.TypeSOA {
			origin = rr.Header().Name
		}

		label := rr.Header().Name
		rrtype := dns.TypeToString[rr.Header().Rrtype]
		if rr.Header().Rrtype == dns.TypeRRSIG {
			rrtype = rrtype + dns.TypeToString[rr.(*dns.RRSIG).TypeCovered]
		}

		if _, ok := cache[label]; !ok {
			cache[label] = make(map[string][]dns.RR)
		}
		if _, ok := cache[label][rrtype]; !ok {
			cache[label][rrtype] = make([]dns.RR, 0)
		}
		cache[label][rrtype] = append(cache[label][rrtype], rr)
	}

	if err := zp.Err(); err != nil {
		panic(err)
	}

	return
}

func hasNSEC(cache Cache) bool {
	for l := range cache {
		if _, ok := cache[l]["NSEC"]; ok {
			return true
		}
	}
	return false
}

func hasNSEC3(cache Cache) bool {
	for l := range cache {
		if _, ok := cache[l]["NSEC3"]; ok {
			return true
		}
	}
	return false
}

// Reverse returns its argument string reversed rune-wise left to right.
func Reverse(s string) []string {
	labels := dns.SplitDomainName(s)
	res := make([]string, 0)
	for i := len(labels) - 1; i >= 0; i = i - 1 {
		res = append(res, labels[i])
	}
	return res
}

func isDelegated(label string, cache Cache, origin string) bool {
	// out of zone, has to be glue
	if !strings.HasSuffix(label, origin) {
		return true
	}

	// origin is not delegated
	if label == origin {
		return false
	}

	numOrigin := dns.CountLabel(origin)
	numLabel := dns.CountLabel(label)
	labels := dns.SplitDomainName(label)

	for i := 0; i < numLabel-numOrigin; i += 1 {
		l := dns.Fqdn(strings.Join(labels[i:numLabel], "."))
		if _, ok := cache[l]; ok {
			if _, ok = cache[l]["NS"]; ok {
				return true
			}
		}
	}

	// no delegation found
	return false
}

func getLabels(cache Cache) []string {
	var labels []string = make([]string, 0)
	for label := range cache {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		li := dns.CountLabel(labels[i])
		lj := dns.CountLabel(labels[j])
		ri := Reverse(labels[i])
		rj := Reverse(labels[j])
		min := li
		if lj < min {
			min = lj
		}
		for n := 0; n < min; n += 1 {
			if ri[n] == rj[n] {
				continue
			}
			return ri[n] < rj[n]
		}
		return li < lj
	})
	return labels
}

func getNsecLabels(cache Cache, origin string) []string {
	var labels []string = make([]string, 0)
	for label := range cache {
		// origin must have nsec records
		if label == origin {
			labels = append(labels, label)
			continue
		}
		// out of zone data should have no nsec records
		if !strings.HasSuffix(label, origin) {
			continue
		}
		/*
			ONLY IN ZONE LABELS BELOW
		*/
		// if the name is a delegation point it has nsec
		if _, ok := cache[label]["NS"]; ok {
			labels = append(labels, label)
			continue
		}
		if !isDelegated(label, cache, origin) {
			// NSEC3 records do not get NSEC records
			if _, ok := cache[label]["NSEC3"]; ok {
				nsec3only := true
				for l := range cache[label] {
					if l != "NSEC3" && l != "RRSIGNSEC3" {
						nsec3only = false
						break
					}
				}
				if nsec3only {
					// no nsec
					continue
				}
			}
			labels = append(labels, label)
			continue
		}
		// this is glue, no nsec
	}

	sort.Slice(labels, func(i, j int) bool {
		li := dns.CountLabel(labels[i])
		lj := dns.CountLabel(labels[j])
		ri := Reverse(labels[i])
		rj := Reverse(labels[j])
		min := li
		if lj < min {
			min = lj
		}
		for n := 0; n < min; n += 1 {
			if ri[n] == rj[n] {
				continue
			}
			return ri[n] < rj[n]
		}
		return li < lj
	})
	return labels
}

func hash2string(digesttype uint8) string {
	if dt, ok := dns.HashToString[digesttype]; ok {
		return dt
	}
	return fmt.Sprintf("DIGESTTYPE%d", digesttype)
}

func algorithm2string(algorithm uint8) string {
	if algStr, ok := dns.AlgorithmToString[algorithm]; ok {
		return algStr
	}
	return fmt.Sprintf("ALGORITHM%d", algorithm)
}

func okAlgorithm(algorithm uint8) bool {
	alg := algorithm2string(algorithm)
	if !viper.IsSet(alg) || !viper.GetBool(alg) {
		return false
	}
	return true
}

func okDigestType(dt uint8) bool {
	dtstr := hash2string(dt)
	if !viper.IsSet(dtstr) || !viper.GetBool(dtstr) {
		return false
	}
	return true
}

func bool2allow(b bool) string {
	if b {
		return "allowed"
	}
	return "not allowed"
}

func checkOnlyAtApex(cache Cache, origin string, rrtype string) (r Result) {
	for label := range cache {
		if label == origin {
			continue
		}
		if _, ok := cache[label][rrtype]; ok {
			log.Errorf("Label %s has %s record.", label, rrtype)
			r.errors++
		}
	}
	return
}

func checkSignedBySEP(cache Cache, origin string, rrtype string) (r Result) {
	for _, rr := range cache[origin]["RRSIG"+rrtype] {
		rrsig := rr.(*dns.RRSIG)
		for _, dd := range cache[origin]["DNSKEY"] {
			dnskey := dd.(*dns.DNSKEY)
			if rrsig.KeyTag == dnskey.KeyTag() && dnskey.Flags&dns.SEP != dns.SEP {
				log.Warnf("%s records signed with ZSK keytag %d", rrtype, dnskey.KeyTag())
				r.warnings++
			}
		}
	}
	return
}
