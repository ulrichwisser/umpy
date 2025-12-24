package main

import (
	"sort"
	"strings"
	"errors"
	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkNSEC3(cache Cache, origin string) (r Result) {
/*

NSEC3 should ***NEVER*** have been invented. What a mess!!!

↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ here be dragons ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓

1. Check if chain is a complete loop
2. CheckNSEC3rr checks if a NSEC3 record follows RFC 9276
3. Check all records use parameters from NSEC3PARAM
4. Check if all records that must have a NSEC3 record have one
5. Check that all NSEC3 records actually have a parent record

*/

	r.Add(checkNSEC3chain(cache, origin))
	r.Add(checkNSEC3rr(cache, origin))
	r.Add(checkNSEC3Labels(cache, origin))
	return
}

// checkNSEC3chain checks if all NSEC3 records in the cache are linked into one chain
func checkNSEC3chain(cache Cache, origin string) (r Result) {

	// extract all labels with an NSEC3 record
	nsec3labels := make([]string, 0)
	for l := range cache {
		if _, ok := cache[l]["NSEC3"]; ok {
			nsec3labels = append(nsec3labels, l)
		}
	}
	sort.Strings(nsec3labels)

	// check if chain is fully linked
	for i := range nsec3labels {
		// only one NSEC3 record per label
		if len(cache[nsec3labels[i]]["NSEC3"]) != 1 {
			log.Errorf("Label %s does have %d NSEC3 records, expected 1", nsec3labels[i], len(cache[nsec3labels[i]]["NSEC3"]))
			r.errors++
			continue
		}

		// index of next label
		nextindex := i + 1
		if nextindex == len(nsec3labels) {
			nextindex = 0
		}

		// easier access to NSEC3 RR
		nsec3 := cache[nsec3labels[i]]["NSEC3"][0].(*dns.NSEC3)

		// check chain
		if nsec3.NextDomain+"."+origin != nsec3labels[nextindex] {
			log.Errorf("NSEC3 record for label %s has %s as next domain. expected %s", nsec3labels[i], nsec3.NextDomain, nsec3labels[nextindex])
			r.errors++
		}
	}

	return
}

// checkNSEC3rr checks if a NSEC3 record follows RFC 9276
// check all records use parameters from NSEC3PARAM
func checkNSEC3rr(cache Cache, origin string) (r Result) {

	// get NSEC3PARAM record (needed to check salt)
	var nsec3param *dns.NSEC3PARAM
	if _, ok := cache[origin]["NSEC3PARAM"]; ok {
		nsec3param = cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	} else {
		log.Error("No NSEC3PARAM found.")
		r.errors++
		return
	}

	for l := range cache {
		if _, ok := cache[l]["NSEC3"]; !ok {
			continue
		}

		// easier access to NSEC3 RR
		nsec3 := cache[l]["NSEC3"][0].(*dns.NSEC3)
		
		// check all values against NSEC3PARAM
		if nsec3.Hash != nsec3param.Hash {
			log.Errorf("Label %s NSEC3 hash algorithm %d differs from NSEC3PARAM hash algorithm %d.", nsec3.Header().Name, nsec3.Hash, nsec3param.Hash)
			r.errors++
		}
        // Only "no flags" or opt-out are defined
        if nsec3.Flags != 0 && nsec3.Flags != 1 {
                log.Errorf("Label %s NSEC3 has flag field with value %d, allowed are 0 or 1.\n", nsec3.Header().Name, nsec3.Flags)
                r.errors++
        }
        // Opt-Out is not recommended, warning can be disabled through config
        if !viper.GetBool(NSEC3_OPTOUTOK) && nsec3.Flags&1 == 1 {
                log.Warnf("Label %s NSEC3 is using opt-out, opt-out is not recommended.\n", nsec3.Header().Name)
                r.warnings++
        }
		if nsec3.Iterations != nsec3param.Iterations {
			log.Errorf("Label %s has NSEC3 iterations of %d, NSEC3PARAM has value %d", nsec3.Header().Name, nsec3.Iterations, nsec3param.Iterations)
			r.errors++
		}
		if nsec3.Salt != nsec3param.Salt {
			log.Errorf("Label %s NSEC3 salt differs from NSEC3PARAM salt. NSEC3 salt: '%s'  NSEC3PARAM salt: '%s'\n", nsec3.Header().Name, nsec3.Salt, nsec3param.Salt)
			r.errors++
		}
	}

	// done
	return
}

type nsec3entity struct {
	hash          string
	originalowner string
	flags         uint8
	temporary     bool
	delegation    bool
	hasds         bool
	types         map[string]bool
}

// checkNSEC3Labels checks if all labels that should have an NSEC3 record have one
// Follow RFC 5155 7.1 to compute all labels that need NSEC3 records
func checkNSEC3Labels(cache Cache, origin string) (r Result) {

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records
		Step 1:

		Select the hash algorithm and the values for salt and iterations.

		Hash algorithm, salt and iterations are given in the nsec3param record
	*/
	var nsec3param *dns.NSEC3PARAM
	if _, ok := cache[origin]["NSEC3PARAM"]; ok {
		nsec3param = cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	} else {
		log.Error("No NSEC3PARAM found.")
		r.errors++
		return
	}

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records
		Step 2:

		For each unique original owner name in the zone add an NSEC3 RR.

		*		If Opt-Out is being used, owner names of unsigned delegations
				MAY be excluded.

		*		The owner name of the NSEC3 RR is the hash of the original
				owner name, prepended as a single label to the zone name.

		*		The Next Hashed Owner Name field is left blank for the moment.

		*		If Opt-Out is being used, set the Opt-Out bit to one.

		*		For collision detection purposes, optionally keep track of the
				original owner name with the NSEC3 RR.

		*		Additionally, for collision detection purposes, optionally
				create an additional NSEC3 RR corresponding to the original
				owner name with the asterisk label prepended (i.e., as if a
				wildcard existed as a child of this owner name) and keep track
				of this original owner name.  Mark this NSEC3 RR as temporary.

		Step 3:

		For each RRSet at the original owner name, set the corresponding
		       bit in the Type Bit Maps field.
	*/

	uniqueOriginalOwnerName := getUniqueOriginalOwnerNames(cache, origin)
	nsec3entities := make(map[string][]nsec3entity, 0)
	for _, label := range uniqueOriginalOwnerName {
		_, hasNS := cache[label]["NS"]
		_, hasDS := cache[label]["DS"]
		labelhash := dns.CanonicalName(dns.HashName(label, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin)
		if _, ok := nsec3entities[labelhash]; !ok {
			nsec3entities[labelhash] = make([]nsec3entity, 0)
		}
		entity := nsec3entity{hash: labelhash, originalowner: label, flags: 0, temporary: false, delegation: hasNS, hasds: hasDS, types: make(map[string]bool, 0)}
		// This for loop implements step 3
		for t := range cache[label] {
			if strings.HasPrefix(t, "RRSIG") {
				entity.types["RRSIG"] = true
			} else {
				entity.types[t] = true
			}
		}
		nsec3entities[labelhash] = append(nsec3entities[labelhash], entity)

		// add temporary wildcard record, if non exists
		wildcardlabel := "*." + label
		wildcardhash := dns.CanonicalName(dns.HashName(wildcardlabel, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin)
		if _, ok := nsec3entities[wildcardhash]; !ok {
			nsec3entities[wildcardhash] = make([]nsec3entity, 0)
		}
		nsec3entities[wildcardhash] = append(nsec3entities[wildcardhash], nsec3entity{hash: wildcardhash, originalowner: wildcardlabel, flags: 0, temporary: true, delegation: false, hasds: false, types: make(map[string]bool, 0)})
	}

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records

		Step 4:

			If the difference in number of labels between the apex and the
			original owner name is greater than 1, additional NSEC3 RRs need
			to be added for every empty non-terminal between the apex and the
			original owner name.  This process may generate NSEC3 RRs with
			duplicate hashed owner names.  Optionally, for collision
			detection, track the original owner names of these NSEC3 RRs and
			create temporary NSEC3 RRs for wildcard collisions in a similar
			fashion to step 1.
*/
	originlabels := dns.SplitDomainName(origin)
	for _, label := range uniqueOriginalOwnerName {

		log.Debugf("Step4: Label %s", label)

		// add additional nsec3 for empty non terminals
		labels := dns.SplitDomainName(label)
		// no empty non terminals
		if len(labels)-len(originlabels) <= 1 {
			continue
		}
		for i := 1; i < len(labels)-len(originlabels); i++ {
			l := dns.Fqdn(strings.Join(labels[i:], "."))
			log.Debugf("    test empty non terminal %s", l)
			log.Debugf("    nsec3param %v", nsec3param)
			lh := dns.CanonicalName(dns.HashName(l, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin)
			log.Debugf("    lh %s", lh)
			// a record exists at the label, no need to insert empty non terminal
			if _, ok := nsec3entities[lh]; ok {
				continue
			} else {
				nsec3entities[lh] = make([]nsec3entity, 0)
			}
			nsec3entities[lh] = append(nsec3entities[lh], nsec3entity{hash: lh, originalowner: l, flags: 0, temporary: false, delegation: false, hasds: false, types: make(map[string]bool, 0)})
			log.Debug("    added")
			wl := "*." + l
			wlh := dns.CanonicalName(dns.HashName(wl, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin)
			log.Debugf("    wl  %s", wl)
			log.Debugf("    wlh %s", wlh)
			if _, ok := nsec3entities[wlh]; !ok {
				nsec3entities[wlh] = make([]nsec3entity, 0)
			}
			nsec3entities[wlh] = append(nsec3entities[wlh], nsec3entity{hash: wlh, originalowner: wl, flags: 0, temporary: true, delegation: false, hasds: false, types: make(map[string]bool, 0)})
		}
	}

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records

		Step 5:

		Sort the set of NSEC3 RRs into hash order.

		Because we use a map, all records are already combined in hash order
		nothing to do
	*/

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records

		Step 6:

		Combine NSEC3 RRs with identical hashed owner names by replacing
		       them with a single NSEC3 RR with the Type Bit Maps field
		       consisting of the union of the types represented by the set of
		       NSEC3 RRs.  If the original owner name was tracked, then
		       collisions may be detected when combining, as all of the matching
		       NSEC3 RRs should have the same original owner name.  Discard any
		       possible temporary NSEC3 RRs.

		We do thingsin order of
		- collision detection
		- delete all temporary nsec3 data
		- combine should be unnecessary, but we do check
	*/
	for label := range nsec3entities {
		// collision detection
		if len(nsec3entities[label]) == 1 {
			for i := 1; i < len(nsec3entities[label]); i++ {
				if nsec3entities[label][0].originalowner != nsec3entities[label][i].originalowner {
					if viper.GetInt("verbose") > 0 {
						log.Warnf("NSEC3 abel %s has a collision, owners: %s %s", label, nsec3entities[label][0].originalowner, nsec3entities[label][i].originalowner)
						r.warnings++
					}
					r.errors++
				}
			}
		}

		// delete all temporary nsec3 data
		i := 0
		for {
			if nsec3entities[label][i].temporary {
				nsec3entities[label] = append(nsec3entities[label][:i], nsec3entities[label][i+1:]...)
				if len(nsec3entities[label]) == 0 {
					break
				}
				i--
			}
			i++
			if i >= len(nsec3entities[label]) {
				break
			}
		}
		if len(nsec3entities[label]) == 0 {
			delete(nsec3entities, label)
			continue
		}

		// combine should be unnecessary, but we do check
		if len(nsec3entities[label]) > 1 {
			if viper.GetInt("verbose") > 0 {
				log.Errorf("Label %s originalowner %s has %d nsec3 rr.", label, nsec3entities[label][0].originalowner, len(nsec3entities[label]))
				r.errors++
			}
			for i = 1; i < len(nsec3entities[label]); i++ {
				if nsec3entities[label][i].hasds {
					nsec3entities[label][0].hasds = true
				}
				if nsec3entities[label][i].delegation {
					nsec3entities[label][0].delegation = true
				}
				for t := range nsec3entities[label][i].types {
					nsec3entities[label][0].types[t] = true
				}
			}
		}
	}

	/*
		Follow RFC 5155 7.1 to compute all labels that need NSEC3 records

		Step 7 and 8:

		Not needed for our purposes
	*/

	/*
	- Check that all needed NSEC3 RR exist
    - Check that no ther NSEC3 RR exist
	*/
	log.Debug("Start checking zone")
	for label := range nsec3entities {
		if _,ok:=cache[label]; !ok {
			log.Debugf("Checking OPTPUT for NSEC3 record %s (original owner %s)", label, nsec3entities[label][0].originalowner)
			// NSEC3 record is missing
			// this is ok if
			// - originalowner is an insecure delegation
            // - enclosing nsec3 record has the optout flag set
			if !isDelegated(nsec3entities[label][0].originalowner, cache, origin) {
				log.Debugf("origianlowner %s is not delegated", nsec3entities[label][0].originalowner)
				log.Errorf("NSEC3 record missing %s (original owner %s)", label, nsec3entities[label][0].originalowner)
				r.errors++
				continue
			}
			nsec3, err := getClosestEncloser(cache, origin, nsec3entities[label][0].originalowner)
			if err != nil {
				log.Fatalf("Could not get closest encloser of %s (original owner %s)", label, nsec3entities[label][0].originalowner)
			}
			log.Debugf("Closes Encloser is %s (original owner %s)", nsec3.Header().Name, nsec3entities[nsec3.Header().Name][0].originalowner)
			log.Debugf("Flags is %d (error if not 1=optout)", nsec3.Flags)
			if nsec3.Flags&1!=1 {
				log.Errorf("NSEC3 record missing %s (original owner %s)", label, nsec3entities[label][0].originalowner)
				r.errors++
				continue
			}
			// closest encloser found and optout flag is set
			continue
		}
		if _,ok:=cache[label]["NSEC3"]; !ok {
			log.Fatalf("NSEC3 should exist for label %s (original owner %s)", label, nsec3entities[label][0].originalowner)
			r.errors++
			continue
		}
		log.Debugf("NSEC3 is found at: %s (original owner: %s)", label, nsec3entities[label][0].originalowner)		
	}
	for label := range cache {
		// We are looking for NSEC3 records
		if _,ok:=cache[label]["NSEC3"]; !ok {
			continue
		}
		// 
		// 		labels := dns.SplitDomainName(label)

		if _,ok:=nsec3entities[label]; !ok {
			log.Errorf("Found NSEC3 record at %s, but it should not be there.", label)
			r.errors++
		}
	}

	// done
	return
}

func getClosestEncloser(cache Cache, origin string, originalowner string) (nsec3 *dns.NSEC3, err error) {

	var nsec3param *dns.NSEC3PARAM
	if _, ok := cache[origin]["NSEC3PARAM"]; ok {
		nsec3param = cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	} else {
		log.Fatal("No NSEC3PARAM found.")
	}

	originlabels := dns.SplitDomainName(originalowner)
	for i := 1; i < len(originlabels); i++ {
			l := dns.Fqdn(strings.Join(originlabels[i:], "."))
			lh := dns.CanonicalName(dns.HashName(l, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin)
			log.Debugf("testing %s %s", l, lh)
			if _,ok := cache[lh]; !ok {
				continue
			}
			if _,ok := cache[lh]["NSEC3"]; !ok {
				continue
			}
			log.Debugf("Found closes encloser of %s at %s (original owner %s)", originalowner, lh, l)
			return cache[lh]["NSEC3"][0].(*dns.NSEC3), nil
		}
	return nil, errors.New("No closest encloser found")
}

func getUniqueOriginalOwnerNames(cache Cache, origin string) (uniqueOriginalOwnerNames []string) {
	// clear text labels which should have an nsec3 record
	uniqueOriginalOwnerNames = make([]string, 0)

	for label := range cache {
		// origin must have nsec records
		if label == origin {
			uniqueOriginalOwnerNames = append(uniqueOriginalOwnerNames, label)
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
			uniqueOriginalOwnerNames = append(uniqueOriginalOwnerNames, label)
			continue
		}
		if isDelegated(label, cache, origin) {
			// glue, no nsec3
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
				// no nsec3
				continue
			}
		}
		uniqueOriginalOwnerNames = append(uniqueOriginalOwnerNames, label)
		continue
	}
	return
}

func checkNSEC3TypeBitmap(cache Cache, origin string) (r Result) {

	// get NSEC3PARAM record 
	var nsec3param *dns.NSEC3PARAM
	if _, ok := cache[origin]["NSEC3PARAM"]; ok {
		nsec3param = cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	} else {
		log.Error("No NSEC3PARAM found.")
		r.errors++
		return
	}


	// all names tht should have a NSEC3 record
	labels := getUniqueOriginalOwnerNames(cache, origin)

	// for all nsec3 hashes check that all entries in tpe bitmap have corresponding RR
	for _,l := range labels {
		hash := dns.CanonicalName(dns.Fqdn(dns.HashName(l, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt) + "." + origin))
		log.Debugf("Label %s  Hash %s", l, hash)

		if _, ok := cache[hash]["NSEC3"]; !ok {
			log.Errorf("Label %s should have a NSEC3 record (%s), but doesn't.", l, hash)
			continue
		}
		
		// get NSEC3 rr
		nsec3 := cache[hash]["NSEC3"][0].(*dns.NSEC3)

		// empty bitmap
		if len(nsec3.TypeBitMap)==0 {
			log.Errorf("NSEC3 record %s has an empty bitmap", l)
			r.errors += 1
			continue
		}

		// compute all types that should be covered
		var typesAtLabel map[uint16]bool = make(map[uint16]bool, 0)
		for typeStr := range cache[l] {
			for _,rr := range cache[l][typeStr] {
				typesAtLabel[rr.Header().Rrtype] = true
			}
		}

		// In bitmap, but no RR
		for _,rrtype := range nsec3.TypeBitMap {
			if !typesAtLabel[rrtype] {
				log.Errorf("Bitmap for NSEC3 record %s contains %s (%d), but no such a record exists at %s", hash, dns.TypeToString[rrtype], rrtype, l)
				r.errors += 1
			}
		}

		// RR exists, no covered in bitmap
		for rrtype := range typesAtLabel {
			var found bool = false
			for _,t := range nsec3.TypeBitMap {
				if t == rrtype {
					found = true
					break
				}
			}
			if !found {
				log.Errorf("At label %s zone contains %s (%d) record(s) but is not covered by NSEC3 record %s", l, dns.TypeToString[rrtype], rrtype, hash)
				r.errors += 1
			}
		}
	}
	return
}
