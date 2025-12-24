[![Issues](https://img.shields.io/github/issues/markdown-templates/markdown-snippets.svg)](https://github.com/markdown-templates/markdown-snippets/issues)
![unit tests](https://github.com/ulrichwisser/umpy/actions/workflows/push.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ulrichwisser/umpy)](https://goreportcard.com/report/github.com/ulrichwisser/umpy)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Creative Commons BYNC-ND 4.0](https://i.creativecommons.org/l/by-nc-nd/4.0/80x15.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)

![UMPY - The DNSSEC referee](https://raw.githubusercontent.com/ulrichwisser/umpy/main/images/umpy.png)


# UMPY - The DNSSEC referee

Umpy takes a DNSSEC signed zone file as input and tries to judge all DNSSEC related resource records.

## Main Features

Umpy checks 

1. Validity of all signatures
1. Completness of the NSEC chain
1. Inception and expiration of all RRSIG
1. DS records are checked for well defined values
1. NSEC3PARAM and NSEC3 records parameters are checked to follow [RFC 9276](https://datatracker.ietf.org/doc/html/rfc9276)
1. TODO: Completness of NSEC3 chain

Please see below for detailed description of all tests performed.

# STATUS

This project is a work in progress!
Currently many parts are under construction.

# Copyright

All code is licensed under [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html).
Artwork is licensed under [![Creative Commons BY-NC-ND 4.0](https://i.creativecommons.org/l/by-nc-nd/4.0/80x15.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)


# Contributing

Contributions are always welcome!

Please note that all submission must be licensed under [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html).

Easiest way to contribute is via pull-request, open an issue or contact the author.


# Benchmarks

Test 1: Average of 100 runs over a .se zonefile.

Test 2: 100 runs over all test zone from jdnssec-tools

| Software | Test 1 | Test 2 |
|----------|--------|--------|
|umpy ||
|ldns-verify ||
|dnssec-verify ||
|jdnssec-verify ||
|kzonecheck ||
|validns ||

TODO: BENCHMARK

# Feature Comparison

| Feature | umpy | ldns-verify | dnssec-verify | jdnssec-verify | kzonecheck |
|---------|------------|-------------|---------------|----------------|------------|

TODO: FEATURE COMPARISON

# Build

TODO: Build for various distributions

# Test

This software comes with a large amount of unit tests, all of which can be run by
```
go test
```
and are automatically run on all pull requests and all updates to the main branch.

Current status: ![unit tests](https://github.com/ulrichwisser/umpy/actions/workflows/push.yml/badge.svg)

If you'd like to run a specific unit test or a specific group of unit tests use
```
go test -run <regexp>
```

# Acknowledgements

Ideas and inspiration from

- validns http://www.validns.net/
- ldns-verify https://nlnetlabs.nl/projects/ldns/about/
- dnssec-verify (part of the bind distribution) https://www.isc.org/bind/
- jdnssec-tools https://github.com/dblacka/jdnssec-tools

## Configuration

umpy can be configured to only run some of the tests and many tests can be
configured. All configuration is done in a config file in YAML format.
By default `~/.umpy` is loaded followed by `./.umpy.` But it can be specified on the
command line `umpy --config  path/to/config.yaml`.

### Command Line Arguments

|          |    | Description |
|----------|----|----------------------------------------------------------------------------|
|--verbose | -v | increase the level of verbosity (1=error,2=warnings,3=info,4=debug)
|--nsec    |    | force to run NSEC checks
|--nsec3   |    | force to run NSEC3 checks
|--norrsig |    | do not run RRSIG checks
|--now     |    | set timestamp for RRSIG evaluation, format: YYYY-MM-DDTHH:MM:SS+0000
|--config  | -f | give a location of a config file to read

### Which tests will be executed

RRSIG will be check unless --norrsig flag is given as command line parameter
DS and DNSKEY records will alwys be tested
NSEC tests are run if NSEC records are found in the zone.
NSEC3 and NSEC3PARAM tests are run if NSEC3 records are found in the zone.

The command line arguments --nsec and --nsec3 can force the respective tests to be run anyways.

## Test Specifications

### CDS

- checks that CDS records are only found at the apex
- checks that CDS RR set is signed by KSK (DNSKEY with SEP flag set)
- checks that all or no CDS records use algorithm 0
- checks if algorithm 0 is used all other fields should follow RFC 8078 section 4 (see errata)
- checks if CDS uses allowed digest type
- checks if CDS uses allowed algorithm
- checks if at least one CDS refers to a DNSKEY record in the DNSKEY RR set that signs the DNSKEY RR set

Configuration: see Allowed Algorithms and Allowed Digest Types

### CDNSKEY

- checks that CDNSKEY records are only found at the apex
- checks that CDNSKEY RR set is signed by KSK (DNSKEY with SEP flag set)
- checks if CDNSKEY refers to a DNSKEY record in the DNSKEY set
- checks if CDNSKEY uses allowed algorithm
- checks if the referred DNSKEY signs the DNSKEY set
- checks that all or no CDNSKEY records use algorithm 0
- checks if algorithm 0 is used all other fields should follow RFC 8078 section 4 (see errata)

Configuration: see Allowed Algorithms

### CDS/CDNSKEY

- checks that CDS and CDNSKEY point to the same keys or both use algorithm zero

### DNSKEY

- checks for existence of DNSKEY records at the apex 
- checks that keys of the same algorithm do not have the same keyTag
- checks that at least one key of each algorithm in the DNSKEY set has the SEP flag set
- checks that all DNSKEY records use an allowed algorithm 
- checks that all keys with SEP flag set sign the DNSKEY set

Configuration: see Allowed Algorithms

### DS

- checks that DS uses allowed digest type
- checks that DS uses allowed algorithm
- checks that a label with a DS record is delegated

Configuration: see Allowed Algorithms and Allowed Digest Types

### NSEC

The command line argument --nsec can force umpy to run this test

- checks that all NSEC records are chained together in one loop, in correct order
- checks that all labels that should have a NSEC record really have one
- checks that all labels that should have a NSEC record have exactly one
- checks that all types in bitmap exist for a label
- checks that all types for a label that exist are covered by NSEC

### NSEC3

- checks that all NSEC3 records are linked in one loop in the right order
- check all NSEC3 records use parameters from NSEC3PARAM
- checks that all types in bitmap exist for a label
- checks that all types for a label that exist are covered by bitmap

- TODO: check that all needed NSEC3 records are in the zone
- TODO: check that all NSEC3 records in the zone are allowed

For configuration see section NSEC3 Configuration

### NSEC3PARAM

- checks that exactly one NSEC3PARAM record is found
- checks NSEC3PARAM against recommendations in [RFC 9276](https://datatracker.ietf.org/doc/html/rfc9276)

For configuration see section NSEC3 Configuration

### RRSIG

- checks that delegated labels are not signed (except DS, NSEC, NSEC3)
- checks that glue is not signed
- checks that not delegated labels are signed (all RR types)
- checks RRSIG inception and expiration timestamp
- checks that all RRSIG records are valid signatures


The timing checks start with the current time. This can be overridden with the
command line argument `--now`.

The following parameters can be set in the configuration file.
As value TTL notation can be used. Numbers are treated as seconds. Example 2h30m5s = 2 hours 30 minutes 5 seconds = 9005

MinAge    inception has to be at least this duration before now (default 4 hours)
MaxAge    inception has to be max this duration old (default 4 days)
MinValid  expiration has to be after this duration (default 21 days)
MaxValid  expiration has to be before this duration (default 30 days)

### SOA

- checks that SOA expire consistent with RRSIG timings

Please see DNSSEC timings for details.

### Allowed Algorithms

The list of allowed algorithms can be configured. It is used for DS records and DNSKEY records.
To allow or forbid a specific algorithm one of the following variables have to be set to true or false.
The list is from the [IANA list of well defined DNSSEC algorithms](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)

| Algorithm | Default value |
|-----------|---------------|
|RSAMD5              | false
|DH                  | false
|DSA                 | false
|RSASHA1             | false
|DSA-NSEC3-SHA1      | false
|RSASHA1-NSEC3-SHA1  | false
|RSASHA256           | true
|RSASHA512           | true
|ECC-GOST            | false
|ECDSAP256SHA256     | true
|ECDSAP384SHA384     | true
|ED25519             | true
|ED448               | true
|INDIRECT            | false
|PRIVATEDNS          | false
|PRIVATEOID          | false

Any not mentioned algorithm is by default forbidden.
To allow an algorithm not in the above list, it's number has to be used as follows

ALGORITHM666 = true

### Allowed Digest Types

The list of allowed digest types can be configured. Digest types from the 
[IANA list](https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml)
can be configured by name

| Digest Type | Default value |
|-------------|---------------|
|SHA1    | false
|SHA256  | true
|GOST94  | false
|SHA384  | true
|SHA512  | true

All other digest types can be configured using  the number like

DIGESTTYPE666 = true

### NSEC3 Configuration

NSEC3 records will be checked against all recommendations in
[RFC 9276](https://datatracker.ietf.org/doc/html/rfc9276)

For the number of allowed iterations can be configured by

MaxNsec3Iterations (default 10)

Please indicate if optout is ok with the following configuration option

Nsec3OptOutOk  (default false)

### DNSSEC timings

To understand DNSSEC timing it easiest to start with the signing procedure.
When a record gets signed the inception timestamp is usually put a few hours in
the past. This is done to avoid validation errors for resolvers with badly synced
time. Signatures than have a validity period, which is used to calculate the
expiration timestamp. Some signers add jitter to make resigning more evenly distributed.

Usually a signature is not renewed every time the signer runs, but reused as
long as the data isn't change. For several reasons, for example caching and disaster 
recovery, signatures are renewed long before they expire. This is the Refresh Period.

Signing Interval is the time between two consequtive runs of the signer.

```
Incpetion          Signing          Resign                           Expiration
   |                  |                |                                  |
   |------------------|----------------|----------------------------------|
   | Inception Offset | Refresh Period |                                  |
                      |              Validity Period                      |
```

Example:
|                | Value |
|----------------|-------|
|Inception Offset|  1h
|Refresh Period  |  4d
|Validity Period | 14d
|Signing Interval|  6h

So a signatures inception date should never be older than 4 days and 1 hour but at least one hour old.
The expiration date should never be further away than 14 days and never less
than 10 days (Validity Period - Refresh Period) away.

This would mean the following configuration values

|         | Value | Description |
|---------|-------|-------------|
|MaxAge   | 4d1h  | (Inception Offset + Refresh Period)
|MinAge   | 1h    | (Inception Offset)
|MinValid | 9d18h | (Validity Period - Refresh Period)
|MaxValid | 14d   | (Validity Period)

In case of any disaster where the signer can not run or no new zone can be
distributed the difference of the Validity Period and the Refresh Period
are the period in which the zone is still fully valid. After this time validity
will slowly decline and after Validity Period has passed the full zone will be
invalid.

Secondary servers continue serving a zone even when the primary server is not
reachable. The expire value in the SOA record defines how long a secondary server
might continue to serve the zone.

To be sure that secondary servers only serve a fully valid zone, the SOA expire
value should be shorter then MinValid.


# Authors

- [@ulrichwisser](https://www.github.com/ulrichwisser)
