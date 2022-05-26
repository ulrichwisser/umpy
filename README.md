[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)

![Logo](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/th5xamgrr6se0x5ro4g6.png)

Validate DNSSEC records in a zonefile


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

# Build

# Test
You will need a zone file. If you do not have one at hand, there are several ccTLDs that allow you to download theirs.
```
dig @zonedata.iis.se se axfr +onesoa > se.zone
validnssec -v se.zone
```
# The details

## Acknowledgements

Ideas and inspiration from

- validns http://www.validns.net/
- ldns-verify https://nlnetlabs.nl/projects/ldns/about/
- dnssec-verify (part of the bind distribution) https://www.isc.org/bind/
- jdnssec-tools https://github.com/dblacka/jdnssec-tools

## Contributing

Contributions are always welcome!

Please note that all submission must be licensed under [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/).

Easiest way to contribute is via pull-request, open an issue or contact the author.

## Running Tests

To run tests, run the following command

```
  make test
```

## Configuration

Validnssec can be configured to only run some of the tests and many tests can be
configured. All configuration is done in a config file in YAML format.
By default `~/.validnssec` is loaded followed by `./.validnssec.` But it can be specified on the
command line `validnssec --config exempel.conf`.

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

Sorry, not implemented yet

TODO: CDS

### CDNSKEY

Sorry, not implemented yet

TODO: CDNSKEY

### DNSKEY

- checks for existence of DNSKEY records at the apex (level error)
- checks that keys of the same algorithm do not have the same keyTag (level warning)
- checks that at least one key of each algorithm in the DNSKEY set has the SEP flag set (level warning)
- checks  that all DNSKEY records use an allowed algorithm (level warning)

TODO: check that all keys with SEP flag sign the DNSKEY set
TODO: check that only keys with SEP set sign the DNSKEY set

Configuration: see Allowed Algorithms

### DS

- checks that DS uses allowed digest type
- checks that DS uses allowed algorithm

TODO: check that label is delegated

Configuration: see Allowed Algorithms and Allowed Digest Types

### NSEC

The command line argument --nsec can force validnssec to run this test

- check that all NSEC records are chained together in one loop, in correct order
- checks that all labels that should have a NSEC record really have one
- checks that all labels that should have a NASEC record have exactly one

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

## Authors

- [@ulrichwisser](https://www.github.com/ulrichwisser)
