package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func readZonefile(zonef io.Reader) (origin string, cache Cache) {
	defer log.Trace("Read Zone File").Stop(nil)
	cache = make(Cache, 0)

	//
	zp := dns.NewZoneParser(zonef, "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Rrtype == dns.TypeSOA {
			origin = rr.Header().Name
		}

		label := dns.CanonicalName(rr.Header().Name)
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

// Reverse returns its argument string reversed rune-wise left to right.
func Reverse(s string) []string {
	labels := dns.SplitDomainName(s)
	res := make([]string, 0)
	for i := len(labels) - 1; i >= 0; i = i - 1 {
		res = append(res, labels[i])
	}
	return res
}

func getLabels(cache Cache) []string {
	defer log.Trace("Get Labels").Stop(nil)
	t0 := time.Now()
	var labels [][]string = make([][]string, 0)
	for label := range cache {
		labels = append(labels, Reverse(label))
	}
	log.Debugf("Get labels unsorted %v",time.Since(t0))

	sort.Slice(labels, func(i, j int) bool {
		li := len(labels[i])
		lj := len(labels[j])
		min := li
		if lj < min {
			min = lj
		}
		for n := 0; n < min; n += 1 {
			if labels[i][n] == labels[j][n] {
				continue
			}
			return labels[i][n] < labels[j][n]
		}
		return li < lj
	})

	var result []string = make([]string,len(labels))
	for i:=range labels {
		rev := make([]string,len(labels[i]))
		for n,m:= 0,len(labels[i])-1; m>=0; n,m = n+1,m-1 {
			rev[n]=labels[i][m]
		}
		result[i] = strings.Join(rev,".")+"."
	}
	log.Debugf("Get labels sorted %v",time.Since(t0))

	return result
}

func getNsecLabels(cache Cache, origin string) []string {
	defer log.Trace("Get NSEC Labels").Stop(nil)
	t0 := time.Now()
	var labels [][]string = make([][]string, 0)
	for label := range cache {
		// origin must have nsec records
		if label == origin {
			labels = append(labels, Reverse(label))
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
			labels = append(labels, Reverse(label))
			continue
		}

		if isDelegated(label, cache, origin) {
			// this is glue, no nsec
			continue
		}

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
				// this is a nsec3 hash, no nsec record needed
				continue
			}
		}

		// zone data, needs an nsec record
		labels = append(labels, Reverse(label))
	}
	log.Debugf("Get NSEC labels unsorted %v",time.Since(t0))

	sort.Slice(labels, func(i, j int) bool {
		li := len(labels[i])
		lj := len(labels[j])
		min := li
		if lj < min {
			min = lj
		}
		for n := 0; n < min; n += 1 {
			if labels[i][n] == labels[j][n] {
				continue
			}
			return labels[i][n] < labels[j][n]
		}
		return li < lj
	})

	var result []string = make([]string,len(labels))
	for i:=range labels {
		rev := make([]string,len(labels[i]))
		for n,m:= 0,len(labels[i])-1; m>=0; n,m = n+1,m-1 {
			rev[n]=labels[i][m]
		}
		result[i] = strings.Join(rev,".")+"."
	}
	log.Debugf("Get NSEC labels sorted %v",time.Since(t0))

	return result
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
