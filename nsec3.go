package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func checkNSEC3(cache Cache, origin string) (r Result) {
	r.Add(checkNSEC3chain(cache, origin))
	r.Add(checkNSEC3Labels(cache, origin))
	return
}

// checkNSEC3chain checks if all NSEC3 records in the cache are linked into one chain
// and if all NSEC3 records follow the recommendations of RFC TBD
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
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("Label %s does have %d NSEC3 records, expected 1\n", nsec3labels[i], len(cache[nsec3labels[i]]["NSEC3"]))
			}
			r.errors++
			continue
		}
		// index of next label
		nextindex := i + 1
		if nextindex == len(nsec3labels) {
			nextindex = 0
		}

		nsec3 := cache[nsec3labels[i]]["NSEC3"][0].(*dns.NSEC3)

		// check NSEC3 record
		r.Add(checkNSEC3rr(nsec3))

		// check chain
		if nsec3.NextDomain+"."+origin != nsec3labels[nextindex] {
			if viper.GetInt("verbose") > 0 {
				fmt.Printf("NSEC3 record for label %s has %s as next domain. expected %s\n", nsec3labels[i], nsec3.NextDomain, nsec3labels[nextindex])
			}
			r.errors++
		}
	}

	return
}

// checkNSEC3rr checks if a NSEC3 record follows RFC TBD
// TODO(uw): Fix RFC number
func checkNSEC3rr(nsec3 *dns.NSEC3) (r Result) {
	// Hash - only allowed value is  SHA-1 == 1
	if nsec3.Hash != dns.SHA1 {
		if viper.GetInt("verbose") > 1 {
			fmt.Printf("Label %s NSEC3 uses an unknown hash algorithm %d. Defined is only SHA-1 (1).\n", nsec3.Header().Name, nsec3.Hash)
		}
		r.errors++
	}
	// Only "no flags" or opt-out are defined
	if nsec3.Flags != 0 && nsec3.Flags != 1 {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("Label %s NSEC3 has flag field with value %d, allowed are 0 or 1.\n", nsec3.Header().Name, nsec3.Flags)
		}
		r.errors++
	}
	// Opt-Out is not recommended, warning can be disabled through config
	if !viper.GetBool(NSEC3_OPTOUTOK) && nsec3.Flags&1 == 1 {
		if viper.GetInt("verbose") > 1 {
			fmt.Printf("Label %s NSEC3 is using opt-out, opt-out is not recommended.\n", nsec3.Header().Name)
		}
		r.warnings++
	}
	// Iterations are recommended to be set to 0
	// Iterations above 10 are considered harmful anf might be treated as bogus
	// number of max iterations can be changed in config
	if int(nsec3.Iterations) > viper.GetInt(NSEC3_MAXITERATIONS) {
		if viper.GetInt("verbose") > 1 {
			fmt.Printf("Label %s has NSEC3 iterations of %d, values above %d are possibly treated as bogus .\n", nsec3.Header().Name, nsec3.Iterations, viper.GetInt(NSEC3_MAXITERATIONS))
		}
		r.errors++
	} else if nsec3.Iterations != 0 {
		if viper.GetInt("verbose") > 1 {
			fmt.Printf("Label %s has NSEC3 iterations of %d, recommended is 0.\n", nsec3.Header().Name, nsec3.Iterations)
		}
		r.warnings++
	}
	// Salt should not be used
	if nsec3.SaltLength > 0 || nsec3.Salt != "" {
		if viper.GetInt("verbose") > 1 {
			fmt.Printf("Label %s NSEC3 uses salt. Using salt is not recommended.\n", nsec3.Header().Name)
		}
		r.warnings++
	}
	// done
	return
}

//
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
		if viper.GetInt("verbose") > 0 {
			fmt.Println("No NSEC3PARAM found.")
		}
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

	uniqueOriginalOwnerName := getUniqueOriginalOwnerName(cache, origin)
	nsec3entities := make(map[string][]nsec3entity, 0)
	for _, label := range uniqueOriginalOwnerName {
		// Opt-out can only be detected when compared to NSEC3 records in zone
		_, hasNS := cache[label]["NS"]
		_, hasDS := cache[label]["DS"]
		labelhash := dns.HashName(label, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt)
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
		if _, ok := nsec3entities[labelhash]; !ok {
			nsec3entities[labelhash] = make([]nsec3entity, 0)
		}
		nsec3entities[labelhash] = append(nsec3entities[labelhash], entity)

		// add temporary wildcard record, if non exists
		wildcardlabel := "*." + label
		wildcardhash := dns.HashName(wildcardlabel, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt)
		if _, ok := nsec3entities[wildcardhash]; !ok {
			nsec3entities[wildcardhash] = make([]nsec3entity, 0)
		}
		nsec3entities[wildcardhash] = append(nsec3entities[wildcardhash], nsec3entity{hash: wildcardhash, originalowner: wildcardlabel, flags: 0, temporary: true, delegation: false, hasds: false})
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

		// add additional nsec3 for empty non terminals
		labels := dns.SplitDomainName(label)
		// no empty non terminals
		if len(labels)-len(originlabels) <= 1 {
			continue
		}
		for i := 1; i < len(labels)-len(originlabels); i++ {
			l := strings.Join(labels[i:], ".")
			lh := dns.HashName(l, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt)
			// a record exists at the label, no need to insert empty non terminal
			if _, ok := nsec3entities[lh]; ok {
				continue
			} else {
				nsec3entities[lh] = make([]nsec3entity, 0)
			}
			nsec3entities[lh] = append(nsec3entities[lh], nsec3entity{hash: lh, originalowner: l, flags: 0, temporary: false, delegation: false, hasds: false})

			wl := "*." + l
			wlh := dns.HashName(wl, nsec3param.Hash, nsec3param.Iterations, nsec3param.Salt)
			if _, ok := nsec3entities[wlh]; !ok {
				nsec3entities[wlh] = make([]nsec3entity, 0)
			}
			nsec3entities[lh] = append(nsec3entities[wlh], nsec3entity{hash: wlh, originalowner: wl, flags: 0, temporary: true, delegation: false, hasds: false})
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
						fmt.Printf("NSEC3 abel %s has a collision, owners: %s %s", label, nsec3entities[label][0].originalowner, nsec3entities[label][i].originalowner)
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
				fmt.Printf("Label %s originalowner %s has %d nsec3 rr.\n", label, nsec3entities[label][0].originalowner, len(nsec3entities[label]))
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

	return
}

func getUniqueOriginalOwnerName(cache Cache, origin string) (uniqueOriginalOwnerName []string) {
	// clear text labels which should have an nsec3 record
	uniqueOriginalOwnerName = make([]string, 0)

	for label := range cache {
		// origin must have nsec records
		if label == origin {
			uniqueOriginalOwnerName = append(uniqueOriginalOwnerName, label)
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
			uniqueOriginalOwnerName = append(uniqueOriginalOwnerName, label)
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
		uniqueOriginalOwnerName = append(uniqueOriginalOwnerName, label)
		continue
	}
	return
}
