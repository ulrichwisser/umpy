![example workflow](https://github.com/ulrichwisser/umpy/actions/workflows/push.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ulrichwisser/umpy)](https://goreportcard.com/report/github.com/ulrichwisser/umpy)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Creative Commons BYNC-ND 4.0](https://i.creativecommons.org/l/by-nc-nd/4.0/80x15.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)

![UMPY - The DNSSEC referee](https://raw.githubusercontent.com/ulrichwisser/umpy/main/images/umpy.png)


# UMPY - The DNSSEC referee


# STATUS

This project is a work in progress!
Currently many parts are under construction.

## Features

1. NSEC chain is complete
2. NSEC3 chain is complete
3. All labels have an NSEC3 hash
4. Age check for all RRSIG
5. Validates all signatures
6. DS records are checked for well defined values
7. NSEC3PARAM and NSEC3 records parameters are checked to follow https://datatracker.ietf.org/doc/draft-ietf-dnsop-nsec3-guidance/

# Copyright

All code is licensed under [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html).
Artwork is licensed under [![Creative Commons BYNC-ND 4.0](https://i.creativecommons.org/l/by-nc-nd/4.0/80x15.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)


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

# Feature Comparison

| Feature | umpy | ldns-verify | dnssec-verify | jdnssec-verify | kzonecheck |
|---------|------------|-------------|---------------|----------------|------------|


# Build

# Test
You will need a zone file. If you do not have one at hand, there are several ccTLDs that allow you to download theirs.
```
dig @zonedata.iis.se se axfr +onesoa > se.zone
umpy -v se.zone
```
# Acknowledgements

Ideas and inspiration from

- validns http://www.validns.net/
- ldns-verify https://nlnetlabs.nl/projects/ldns/about/
- dnssec-verify (part of the bind distribution) https://www.isc.org/bind/
- jdnssec-tools https://github.com/dblacka/jdnssec-tools

## Running Tests

To run tests, run the following command

```
  make test
```

## Configuration

umpy can be configured to only run some of the tests and many tests can be
configured. All configuration is done in a config file in YAML format.
By default `~/.umpy` is loaded followed by `./.umpy.` But it can be specified on the
command line `umpy --config exempel.conf`.

### Command Line Arguments

|          |    | Description |
|----------|----|----------------------------------------------------------------------------|
|--verbose | -v | increase the level of verbosity (1=error,2=warnings,3=info,4=debug)
|--nsec    |    | force to run NSEC checks
|--nsec3   |    | force to run NSEC3 checks
|--norrsig |    | do nor run RRSIG checks
|--now     |    | set timestamp for RRSIG evaluation, format: YYYY-MM-DDTHH:MM:SS+0000
|--config  | -f | give a location of a config file to read

### Which tests will be executed

DS and DNSKEY records will alwys be tested
NSEC tests are run if NSEC records are found in the zone.
NSEC3 and NSEC3PARAM tests are run if NSEC3 records are found in the zone.

The command line arguments --nsec and --nsec3 can force the respective tests to be run anyways.

The command line argument --norrsig can stop the RRSIG tests from being executed.

### CDS

- checks if CDS uses allowed digest type
- checks if CDS uses allowed algorithm
- checks if CDS refers to a DNSKEY record in the DNSKEY set
- checks if the referred DNSKEY signs the DNSKEY set
- checks that CDS records are only found at the apex
- checks that all or no CDS records use algorithm 0
- checks if algorithm 0 is used all other fields should follow RFC 8078 section 4 (see errata)
- disable DNSKEY checks if algorithm 0 is used
- checks that CDS RR set is signed by KSK (DNSKEY with SEP flag set)

Configuration: see Allowed Algorithms and Allowed Digest Types

### CDNSKEY

Sorry, not implemented yet

- checks if CDNSKEY uses an allowed algorithm
- checks that the referred DNSKEY is in the DNSKEY set
- checks that the referred DNSKEY signs the DNSKEY set

Configuration: see Allowed Algorithms

TODO: CDNSKEY

### CDS/CDNSKEY

TODO: - checks that CDS and CDNSKEY point to the same keys or both use algorithm zero

### DNSKEY

- checks for existence of DNSKEY records at the apex (level error)
- checks that keys of the same algorithm do not have the same keyTag (level warning)
- checks that at least one key of each algorithm in the DNSKEY set has the SEP flag set (level warning)
- checks  that all DNSKEY records use an allowed algorithm (level warning)
- checks that all keys with SEP flag set sign the DNSKEY set

Configuration: see Allowed Algorithms

### DS

- checks that DS uses allowed digest type
- checks that DS uses allowed algorithm
- checks that a label with a DS record is delegated

Configuration: see Allowed Algorithms and Allowed Digest Types

### NSEC

The command line argument --nsec can force umpy to run this test

- check that all NSEC records are chained together in one loop, in correct order
- checks that all labels that should have a NSEC record really have one
- checks that all labels that should have a NSEC record have exactly one

TODO: check that any other labels do not have a NSEC record

### NSEC3

- checks that all NSEC3 records are linked in one loop in the right order
- checks all NSEC3 records against recommendations in
  https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance

TODO: check that all needed NSEC3 records are in the zone

TODO: check that all NSEC3 records in the zone are allowed

For configuration see section NSEC3 Configuration

### NSEC3PARAM

- checks that exactly one NSEC3PARAM record is found
- checks NSEC3PARAM against recommendations in
  https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance

For configuration see section NSEC3 Configuration

### RRSIG

- checks that delegated labels are not signed (except DS, NSEC, NSEC3)
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
The list is from the IANA list of well defined DNSSEC algorithms
https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml

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

The list of allowed digest types can be configured. Digest types from the IANA list
https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml can be configured by name

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
https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance

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
long as the data doesn't change. That is of course as long as the signature is
valid.

For several reasons as caching and disaster recovery signatures are usually
renewed long before they expire.

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
The expiration date should never be further way than 14 days and never less
than 10 days (Validity Period - Refresh Period) away.

This would mean the following configuration values

|         | Value | Description |
|---------|-------|-------------|
|MaxAge   | 4d6h  | (Inception Offset + Signing Interval)
|MinAge   | 1h    | (Inception Offset)
|MinValid | 9d18h | (Validity Period - Refresh Period - Signing Interval)
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

### Multi Signer DNSSEC


## Authors

- [@ulrichwisser](https://www.github.com/ulrichwisser)
