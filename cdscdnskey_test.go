package main

import (
	"strings"
	"testing"
	"github.com/apex/log"
)

var cdscdnskeyTestZone0 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
`
var cdscdnskeyTestZone1 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDNSKEY 0 3 0 AA=
`
var cdscdnskeyTestZone2 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS 12345   8  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
`
var cdscdnskeyTestZone3 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
`
var cdscdnskeyTestZone4 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
`
var cdscdnskeyTestZone5 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
test-cds.example.  300 IN CDNSKEY 0 3 0 AA=
`
var cdscdnskeyTestZone6 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
test-cds.example.  300 IN CDNSKEY 0 3 0 AA=
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
`
var cdscdnskeyTestZone7 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
`
var cdscdnskeyTestZone8 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600 IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
`
var cdscdnskeyTestZone9 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600 IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
`

func TestCheckCDSCDNSKEY(t *testing.T) {
	cases := []struct {
		Zone     string
		Result
	}{
		{cdscdnskeyTestZone0, Result{0, 0}},
		{cdscdnskeyTestZone1, Result{0, 0}},
		{cdscdnskeyTestZone2, Result{0, 0}},
		{cdscdnskeyTestZone3, Result{0, 0}},
		{cdscdnskeyTestZone4, Result{0, 0}},
		{cdscdnskeyTestZone5, Result{0, 0}},
		{cdscdnskeyTestZone6, Result{0, 0}},
		{cdscdnskeyTestZone7, Result{1, 0}},
		{cdscdnskeyTestZone8, Result{1, 0}},
		{cdscdnskeyTestZone9, Result{2, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		
		log.Debugf("TESTCASE %d",i)

		if r := checkCDSCDNSKEY(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkCDSCDNSKEY expected %d errors and %d warnings, found %d errors and %d warnings..", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}
