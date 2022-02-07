# validnssec
Validate DNSSEC records in a zonefile

validnssec performes the following checks

1. NSEC chain is complete
2. NSEC3 chain is complete
3. All labels have an NSEC3 hash
4. Age check for all RRSIG
5. Validates all signatures

Currently the values for the age check are hardcoded. 
TODO: make age check configuration

# Test
You will need a zone file. If you do not have one at hand, there are several ccTLDs that allow you to download theirs.
```
dig @zonedata.iis.se se axfr +onesoa > se.zone
validnssec -v se.zone
```
