package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const DEFAULT_MAXAGE = 4 * 24 * 60 * 60
const DEFAULT_MINVALID = 10 * 24 * 60 * 60
const DEFAULT_MAXVALID = 20 * 24 * 60 * 60

type Cache map[string]map[string][]dns.RR

var verbose bool = false
var maxage uint = DEFAULT_MAXAGE
var minvalid uint = DEFAULT_MINVALID
var maxvalid uint = DEFAULT_MAXVALID

func main() {

	// define and parse command line arguments

	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.UintVar(&maxage, "m", DEFAULT_MAXAGE, "print more information while running")
	flag.UintVar(&minvalid, "n", DEFAULT_MINVALID, "print more information while running")
	flag.UintVar(&maxvalid, "o", DEFAULT_MAXVALID, "print more information while running")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [-v] zonefile \n", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}

	//
	// ZONE FILE
	//
	zonef, err := os.Open(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	var foundNSEC = false
	var foundNSEC3 = false
	var origin string = ""
	var keys []dns.RR = make([]dns.RR, 0)
	var zonecache Cache = make(Cache, 0)
	var nsec3cache Cache = make(Cache, 0)
	var nsec3param *dns.NSEC3PARAM

	zp := dns.NewZoneParser(zonef, "", "")

	//
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Rrtype == dns.TypeSOA {
			origin = rr.Header().Name
		}
		if rr.Header().Rrtype == dns.TypeNSEC {
			foundNSEC = true
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			foundNSEC3 = true
		}
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			keys = append(keys, rr)
		}
		if rr.Header().Rrtype == dns.TypeNSEC3PARAM {
			nsec3param = rr.(*dns.NSEC3PARAM)
		}

		label := rr.Header().Name
		rrtype := dns.TypeToString[rr.Header().Rrtype]
		if rr.Header().Rrtype == dns.TypeRRSIG {
			rrtype = rrtype + dns.TypeToString[rr.(*dns.RRSIG).TypeCovered]
		}
		if rrtype == "NSEC3" || rrtype == "RRSIGNSEC3" {
			if _, ok := nsec3cache[label]; !ok {
				nsec3cache[label] = make(map[string][]dns.RR)
			}
			if _, ok := nsec3cache[label][rrtype]; !ok {
				nsec3cache[label][rrtype] = make([]dns.RR, 0)
			}
			nsec3cache[label][rrtype] = append(nsec3cache[label][rrtype], rr)
			continue
		}

		if _, ok := zonecache[label]; !ok {
			zonecache[label] = make(map[string][]dns.RR)
		}
		if _, ok := zonecache[label][rrtype]; !ok {
			zonecache[label][rrtype] = make([]dns.RR, 0)
		}
		zonecache[label][rrtype] = append(zonecache[label][rrtype], rr)
	}
	zonef.Close()

	if err := zp.Err(); err != nil {
		panic(err)
	}

	if verbose {
		fmt.Printf("Zonefile successfully read.")
		if foundNSEC {
			fmt.Println("NSEC chain found.")
		}
		if foundNSEC3 {
			fmt.Println("NSEC3 chain found.")
		}
	}

	nsecChainErrors := 0
	nsec3ChainErrors := 0
	sigErrors := 0

	zonelabels := getLabels(zonecache)

	if foundNSEC {
		if verbose {
			fmt.Println("Start checking NSEC chain")
		}
		nsecChainErrors = checkNSEC(zonelabels, zonecache)
	}
	if foundNSEC3 {
		if verbose {
			fmt.Println("Start checking NSEC3 chain")
		}
		nsec3labels := getLabels(nsec3cache)
		nsec3ChainErrors = checkNSEC3(origin, nsec3cache)
		// check if NSEC3 RRSIG validate
		nsec3ChainErrors += checkSignatures(nsec3labels, nsec3cache, keys, origin)
		nsec3ChainErrors += checkNSEC3Labels(nsec3cache, zonecache, zonelabels, nsec3param, origin)
	}

	if verbose {
		fmt.Println("Start checking RRSIG signatures")
	}
	sigErrors = checkSignatures(zonelabels, zonecache, keys, origin)

	// Print results
	if foundNSEC {
		fmt.Println("NSEC Chain Errors: ", nsecChainErrors)
	}
	if foundNSEC3 {
		fmt.Println("NSEC3 Chain Errors: ", nsec3ChainErrors)
	}
	fmt.Println("RRSIG Signature Errors: ", sigErrors)
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

func checkNSEC(labels []string, cache Cache) int {
	chainErrors := 0
	for i := 0; i < len(labels); i += 1 {
		if _, ok := cache[labels[i]]["NSEC"]; !ok {
			if verbose {
				fmt.Printf("Label %s does not have a NSEC record\n", labels[i])
			}
			chainErrors += 1
			continue
		}
		nextindex := i + 1
		if nextindex == len(labels) {
			nextindex = 0
		}
		for _, nsec := range cache[labels[i]]["NSEC"] {
			if nsec.(*dns.NSEC).NextDomain != labels[nextindex] {
				if verbose {
					fmt.Printf("NSEC record for label %s has %s as next domain. expected %s\n", labels[i], nsec.(*dns.NSEC).NextDomain, labels[nextindex])
				}
				chainErrors += 1
			}
		}
	}
	return chainErrors
}

func checkNSEC3(origin string, nsec3cache Cache) int {
	nsec3labels := make([]string, 0)
	for l := range nsec3cache {
		nsec3labels = append(nsec3labels, l)
	}
	sort.Strings(nsec3labels)
	chainErrors := 0

	// check if chain is fully linked
	for i := 0; i < len(nsec3labels); i += 1 {
		if _, ok := nsec3cache[nsec3labels[i]]["NSEC3"]; !ok {
			if verbose {
				fmt.Printf("Label %s does not have a NSEC3 record\n", nsec3labels[i])
			}
			chainErrors += 1
			continue
		}
		nextindex := i + 1
		if nextindex == len(nsec3labels) {
			nextindex = 0
		}
		for _, nsec := range nsec3cache[nsec3labels[i]]["NSEC3"] {
			if nsec.(*dns.NSEC3).NextDomain+"."+origin != nsec3labels[nextindex] {
				if verbose {
					fmt.Printf("NSEC3 record for label %s has %s as next domain. expected %s\n", nsec3labels[i], nsec.(*dns.NSEC3).NextDomain, nsec3labels[nextindex])
					//fmt.Println(nsec)
				}
				chainErrors += 1
			}
		}
	}

	return chainErrors
}

func checkNSEC3Labels(nsec3cache Cache, zonecache Cache, zonelabels []string, nsec3param *dns.NSEC3PARAM, origin string) int {
	labelerror := 0
	for _, label := range zonelabels {
		if _, ok := zonecache[label]["DS"]; !ok && isDelegated(label, zonecache, origin) {
			continue
		}
		nlabel := dns.HashName(label, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt)
		if _, ok := nsec3cache[nlabel+"."+origin]; !ok {
			if verbose {
				fmt.Printf("Label %s has NSEC3 hash %s, which was not found.\n", label, nlabel)
			}
			labelerror += 1
		}
	}
	return labelerror
}

func checkSignatures(labels []string, cache Cache, keys []dns.RR, origin string) int {
	sigErrors := 0
	now := uint32(time.Now().Unix())
	for _, label := range labels {
		for rrtype := range cache[label] {
			if strings.HasPrefix(rrtype, "RRSIG") {
				continue
			}

			if rrtype == "NS" && label != origin {
				// delegation is not signed
				continue
			}

			if isDelegated(label, cache, origin) {
				// label is delegated, no signatures should exist, except DS and NSEC
				if rrtype != "DS" && rrtype != "NSEC" && rrtype != "NSEC3" {
					if _, ok := cache[label]["RRSIG"+rrtype]; ok {
						if verbose {
							fmt.Printf("Label %s is delegated, but RR type %s is signed", label, rrtype)
						}
						sigErrors += 1
						continue
					}
					// this is good, no signature exists, so nothing to do
					continue
				}
			}

			// check existence of signatures
			if _, ok := cache[label]["RRSIG"+rrtype]; !ok || len(cache[label]["RRSIG"+rrtype]) == 0 {
				if verbose {
					fmt.Printf("No signature for %s %s\n", label, rrtype)
				}
				sigErrors += 1
				continue
			}

			// check timing
			for _, rr := range cache[label]["RRSIG"+rrtype] {
				if rr.(*dns.RRSIG).Inception >= now {
					if verbose {
						fmt.Printf("Signature for %s %s has a future inception date %s\n", label, rrtype, dns.TimeToString(rr.(*dns.RRSIG).Inception))
					}
					sigErrors += 1
				}
				if rr.(*dns.RRSIG).Inception < now-uint32(maxage) {
					if verbose {
						fmt.Printf("Signature for %s %s is to old. Inception is %s, min allowed %s\n", label, rrtype, dns.TimeToString(rr.(*dns.RRSIG).Inception), dns.TimeToString(now-uint32(maxage)))
					}
					sigErrors += 1
				}
				if rr.(*dns.RRSIG).Expiration < now+uint32(minvalid) {
					if verbose {
						fmt.Printf("Signature for %s %s expires too soon. Expiration is %s, min allowed %s.\n", label, rrtype, dns.TimeToString(rr.(*dns.RRSIG).Expiration), dns.TimeToString(now+uint32(minvalid)))
					}
					sigErrors += 1
				}
				if rr.(*dns.RRSIG).Expiration > now+uint32(maxvalid) {
					if verbose {
						fmt.Printf("Signature for %s %s expires too late. Expiration is %s, min allowed %s.\n", label, rrtype, dns.TimeToString(rr.(*dns.RRSIG).Expiration), dns.TimeToString(now+uint32(maxvalid)))
					}
					sigErrors += 1
				}
			}

			// validate signatures
			if !checkRRSIG(keys, cache[label][rrtype], cache[label]["RRSIG"+rrtype]) {
				if verbose {
					fmt.Printf("Signature for %s %s did not validate\n", label, rrtype)
				}
				sigErrors += 1
			}
		}

	}
	return sigErrors
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

	num_origin := dns.CountLabel(origin)
	num_label := dns.CountLabel(label)
	labels := dns.SplitDomainName(label)

	for i := 0; i < num_label-num_origin; i += 1 {
		l := dns.Fqdn(strings.Join(labels[i:num_label], "."))
		if _, ok := cache[l]; ok {
			if _, ok = cache[l]["NS"]; ok {
				//fmt.Printf("%s is delegated to %s\n", label, l)
				return true
			}
		}
	}

	// label is not in cache
	//fmt.Printf("%s is not delegated\n", label)
	return false
}

func checkRRSIG(keys []dns.RR, rrset []dns.RR, rrsigs []dns.RR) bool {

	// Check parameters
	if len(keys) == 0 || !dns.IsRRset(keys) || keys[0].Header().Rrtype != dns.TypeDNSKEY {
		if verbose {
			fmt.Printf("First parameter is not a DNSKEY set\n")
		}
		return false
	}
	if len(rrset) == 0 || !dns.IsRRset(rrset) {
		if verbose {
			fmt.Printf("Second parameter is not a RR set\n")
		}
		return false
	}
	if len(rrsigs) == 0 || !dns.IsRRset(rrsigs) || rrsigs[0].Header().Rrtype != dns.TypeRRSIG {
		if verbose {
			fmt.Printf("Third parameter is not a RRSIG set\n")
		}
		return false
	}

	// now check the signature
	for _, key := range keys {
		for _, rrsig := range rrsigs {
			err := rrsig.(*dns.RRSIG).Verify(key.(*dns.DNSKEY), rrset)
			if err == nil {
				return true
			}
		}
	}

	return false
}

func getLabels(cache Cache) []string {
	if verbose {
		fmt.Println("Start get labels")
	}
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
	if verbose {
		fmt.Println("Found ", len(labels), " labels")
	}
	return labels
}
