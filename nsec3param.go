package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// checking for sane NSEC3 parameters https://datatracker.ietf.org/doc/draft-ietf-dnsop-nsec3-guidance/

func checkNSEC3PARAM(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["NSEC3PARAM"]; !ok {
		if viper.GetInt("verbose") > 0 {
			fmt.Println("No NSEC3PARAM record found at apex.")
		}
		r.errors += 1
		return
	}
	if len(cache[origin]["NSEC3PARAM"]) > 1 {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("Found %d NSEC3PARAM records at apex.\n", len(cache[origin]["NSEC3PARAM"]))
		}
		r.errors += 1
		return
	}
	nsec3param := cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	if nsec3param.Hash != dns.SHA1 {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("NSEC3PARAM hash algorithm must specify SHA1 (1), value is %d.\n", nsec3param.Hash)
		}
		r.errors += 1
	}
	if nsec3param.Flags != 0 {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("NSEC3PARAM flags should be zero, value is %d.\n", nsec3param.Flags)
		}
		r.errors += 1
	}

	if int(nsec3param.Iterations) > viper.GetInt(NSEC3_MAXITERATIONS) {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("NSEC3PARAM iterations should be zero, value is %d. Values above %d are possibly treated as bogus.\n", nsec3param.Iterations, viper.GetInt(NSEC3_MAXITERATIONS))
		}
		r.errors += 1
	} else if nsec3param.Iterations != 0 {
		if viper.GetInt("verbose") > 0 {
			fmt.Printf("NSEC3PARAM iterations should be zero, value is %d.\n", nsec3param.Iterations)
		}
		r.warnings += 1
	}

	if nsec3param.SaltLength != 0 || nsec3param.Salt != "" {
		if viper.GetInt("verbose") > 0 {
			fmt.Println("NSEC3PARAM salt should not be used.")
		}
		r.warnings += 1
	}
	return
}
