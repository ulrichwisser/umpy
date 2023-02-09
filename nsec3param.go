package main

import (
	"github.com/apex/log"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// checking for sane NSEC3 parameters RFC9276 https://datatracker.ietf.org/doc/html/rfc9276

func checkNSEC3PARAM(cache Cache, origin string) (r Result) {
	if _, ok := cache[origin]["NSEC3PARAM"]; !ok {
		log.Error("No NSEC3PARAM record found at apex.")
		r.errors += 1
		return
	}
	if len(cache[origin]["NSEC3PARAM"]) > 1 {
		log.Errorf("Found %d NSEC3PARAM records at apex.", len(cache[origin]["NSEC3PARAM"]))
		r.errors += 1
		return
	}
	nsec3param := cache[origin]["NSEC3PARAM"][0].(*dns.NSEC3PARAM)
	if nsec3param.Hash != dns.SHA1 {
		log.Errorf("NSEC3PARAM hash algorithm must specify SHA1 (1), value is %d.", nsec3param.Hash)
		r.errors += 1
	}
	if nsec3param.Flags != 0 {
		log.Errorf("NSEC3PARAM flags should be zero, value is %d.", nsec3param.Flags)
		r.errors += 1
	}

	if int(nsec3param.Iterations) > viper.GetInt(NSEC3_MAXITERATIONS) {
		log.Errorf("NSEC3PARAM iterations should be zero, value is %d. Values above %d are possibly treated as bogus.", nsec3param.Iterations, viper.GetInt(NSEC3_MAXITERATIONS))
		r.errors += 1
	} else if nsec3param.Iterations != 0 {
		log.Errorf("NSEC3PARAM iterations should be zero, value is %d.", nsec3param.Iterations)
		r.warnings += 1
	}

	if nsec3param.SaltLength != 0 || nsec3param.Salt != "" {
		log.Error("NSEC3PARAM salt should not be used.")
		r.warnings += 1
	}
	return
}
