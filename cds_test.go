package main

import (
	"strings"
	"testing"
	"github.com/miekg/dns"
	"github.com/apex/log"
)

var cdsZoneString0 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
`
var cdsZoneString1 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS 12345   8  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
`
var cdsZoneString2 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00=
test-cds.example.  300 IN CDS     1   0  0 00=
test-cds.example.  300 IN CDS     0   0  1 00=
test-cds.example.  300 IN CDS     0   0  0 AA=
test-cds.example.  300 IN CDS 12345   8  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
`
var cdsZoneString3 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     1   0  0 00
`
var cdsZoneString4 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN A 1.2.3.4
`
var cdsZoneString5 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  17 00
`
var cdsZoneString6 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 0
`
var cdsZoneString7 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 FF=
`
var cdsZoneString8 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 AAFF
`
var cdsZoneString9 string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
`
var cdsZoneStringA string = `
test-cds.example.	600	IN SOA	test.example. mail.example. 1410271268 7200	3600	14d 	600
test-cds.example.  300 IN CDS     0   0  0 00
test-cds.example.  300 IN CDS 12345   8  2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A
`


var cdsZoneStringB string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 8 2 600 20300101000000 20230101000000 38170 test-cds.example. beCmbakPpwwBj2Vv+oiSV8RMcHhtpHs94JXC+7reycAsnFvByTq4YSqG2RvU+8R9vvT3ATMyp0PO0KvQOzknPA==
test-cds.example.	600	IN	RRSIG	SOA 13 2 600 20300101000000 20230101000000 40624 test-cds.example. zEhkVdZnCdxQAGI9TsEbSwcXUs9FioL+W87wpn6wYMZ3Mmo8AQB14NOXzjv1hvnuLF2k4DLyNDMHRSjlPKcvCg==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. Dxs5P5ag64CvWcm6Cfq1I1b+gl7+M9wrI+cfAxbZBhPX09fgVYKf0wplLrWfbP6fHm/xShAcl+3sub27xLr0+w==
test-cds.example.	600	IN	RRSIG	DNSKEY 13 2 600 20300101000000 20230101000000 31714 test-cds.example. sYM2JMap2z/skWmSh/i7DSZIvHhsGxgZLTn9QXIh1TU7DeyM4hOKuF0uCjWuedCMioWaSpcuWLLjVa5SVd3Wlw==
test-cds.example.	600	IN	RRSIG	DNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. t7NcQCBcXD8v3zzQIHdKfkguRT15aP6GEvAO2FisvlAFNuQVYBIL+AkWIwa0H9sEzxHJRAgBhhI/pbHDlbKTBw==
test-cds.example.	600	IN	CDS	31714 13 2 f83329c878c3dd867b82607e049ef237ea13a84af60512aedaf604a8bad6ff4a
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDS	57655 15 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	RRSIG	CDS 8 2 600 20300101000000 20230101000000 47084 test-cds.example. F/VV8vxhFf4Fd4bmxVmp3TkE2F7GhN4mBV2i5042yXOk+j3ZV/ySK3ugYKzosXh5ghZp3UutoXMeV/A+uK3KWQ==
test-cds.example.	600	IN	RRSIG	CDS 13 2 600 20300101000000 20230101000000 31714 test-cds.example. gQJG7DJxbRf1nG0mS7vtUTa2uII2V+E4fssmgivSwKDfsFdU/dvUrMFsp5y9//cnfsyDmqh0dzR/VFTvwCVewg==
test-cds.example.	600	IN	RRSIG	CDS 15 2 600 20300101000000 20230101000000 57655 test-cds.example. 1BhrxlwqFzLyO4p0I3nN7W6pTlFNgFjKSrOtSsAoacDZJGpZMLQey3nZDL0gPcE5kVNZ/3i2Pti0G9kMReThCw==
test-cds.example.	600	IN	CDNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w==
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
test-cds.example.	600	IN	CDNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig==
test-cds.example.	600	IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU=
test-cds.example.	600	IN	RRSIG	CDNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. dI2Rb6BZOPHkqn2XUL011fNIaj6r7Z18IMT00Kfgn9TXDr1cl6F/0Ncz9sndYNJ8WVRm3Bi7p9Z8Z6zjbDZazA==
test-cds.example.	600	IN	RRSIG	CDNSKEY 13 2 600 20300101000000 20230101000000 31714 test-cds.example. C2rPUaw7j8EuiJIYTsfpKgnPDA3I5sLriVyI1PBD9EXoCbZd1wmOz+N4kqVmkBCdMsLdUkkoAttXL5yq3jPMWA==
test-cds.example.	600	IN	RRSIG	CDNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. NQ3Gvcymqa/C70SITYj0Lxujlvufinooiyi8mm+6NiRsiRua1+4aZ0xjbcntIKISTvrYDuqvqMIoQd8H5ip7DA==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 8 2 600 20300101000000 20230101000000 38170 test-cds.example. kZ6KPukOpc10lmrlUzIJoJhg60DyGHSc1rGqzQLZTUsSrPOQMY7NY3RxBK20goMadedZ6HsAe/kJ76Gmr7AyEw==
test-cds.example.	600	IN	RRSIG	NSEC 13 2 600 20300101000000 20230101000000 40624 test-cds.example. 4cRQIH4PMsG6WBgL6DUCHMyZTGP/+rgLa4nsGtBQZ8bb7FRtUPfRWlu7YzthTEuKh5ykpV+FAqGDj6b2wLeVgQ==
;
`
var cdsZoneStringC string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 8 2 600 20300101000000 20230101000000 47084 test-cds.example. BknpyiBfW6eVq+YJfGOJS46WT3UYnWvQqZ8IG8cJe0cvUuJdaip9rqyYupETAHNOBh0qTh72PhmDwrsmdmetIg==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. Dxs5P5ag64CvWcm6Cfq1I1b+gl7+M9wrI+cfAxbZBhPX09fgVYKf0wplLrWfbP6fHm/xShAcl+3sub27xLr0+w==
test-cds.example.	600	IN	CDS	31714 13 2 f83329c878c3dd867b82607e049ef237ea13a84af60512aedaf604a8bad6ff4a
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDS	57655 15 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	RRSIG	CDS 8 2 600 20300101000000 20230101000000 47084 test-cds.example. F/VV8vxhFf4Fd4bmxVmp3TkE2F7GhN4mBV2i5042yXOk+j3ZV/ySK3ugYKzosXh5ghZp3UutoXMeV/A+uK3KWQ==
test-cds.example.	600	IN	CDNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w==
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
test-cds.example.	600	IN	CDNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig==
test-cds.example.	600	IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU=
test-cds.example.	600	IN	RRSIG	CDNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. dI2Rb6BZOPHkqn2XUL011fNIaj6r7Z18IMT00Kfgn9TXDr1cl6F/0Ncz9sndYNJ8WVRm3Bi7p9Z8Z6zjbDZazA==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 8 2 600 20300101000000 20230101000000 47084 test-cds.example. fyvI/R/tsgjPebsBgurh8zZ2MlX18q1LuK1AMiF+jO9Vi7R7C8CtuE+Gn1i89KogEvQYKX9890RvZMEXG9TZ9A==
;
`
var cdsZoneStringD string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 13 2 600 20300101000000 20230101000000 40624 test-cds.example. DURX+ao8Fffxu2KRSEHMW1P/whoOxoBesCIDvC4UgbMloPQrlisbrH63BRHaSJDEC0OiEIKP7ppgio2337og3Q==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. Dxs5P5ag64CvWcm6Cfq1I1b+gl7+M9wrI+cfAxbZBhPX09fgVYKf0wplLrWfbP6fHm/xShAcl+3sub27xLr0+w==
test-cds.example.	600	IN	RRSIG	DNSKEY 13 2 600 20300101000000 20230101000000 40624 test-cds.example. pz7mMmM7BdyTrH3D1i06eBZzFyEWiWxHOE/FVe1ud6mDaRZteyXkyVOXrvtvOBWu14UiOMsqd0Xn8gW4Xi9pXw==
test-cds.example.	600	IN	CDS	31714 13 2 f83329c878c3dd867b82607e049ef237ea13a84af60512aedaf604a8bad6ff4a
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDS	57655 15 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	RRSIG	CDS 8 2 600 20300101000000 20230101000000 47084 test-cds.example. F/VV8vxhFf4Fd4bmxVmp3TkE2F7GhN4mBV2i5042yXOk+j3ZV/ySK3ugYKzosXh5ghZp3UutoXMeV/A+uK3KWQ==
test-cds.example.	600	IN	RRSIG	CDS 13 2 600 20300101000000 20230101000000 40624 test-cds.example. LxIfSXY5GkuCh3TPYOgdBmjdhQ9sD4bq9pm6EscGbtqkwjF1ruupijBZfNMzkHy7Ny4lBiEIaCz4tJjgJHpBGQ==
test-cds.example.	600	IN	CDNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w==
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
test-cds.example.	600	IN	CDNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig==
test-cds.example.	600	IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU=
test-cds.example.	600	IN	RRSIG	CDNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. dI2Rb6BZOPHkqn2XUL011fNIaj6r7Z18IMT00Kfgn9TXDr1cl6F/0Ncz9sndYNJ8WVRm3Bi7p9Z8Z6zjbDZazA==
test-cds.example.	600	IN	RRSIG	CDNSKEY 13 2 600 20300101000000 20230101000000 40624 test-cds.example. rjc6+rC2X9vfJjppCiLgUZXuE6k1UFXBsiv/GqXzTmfcNTwEHWfxUVjZElHkLnfqGc4i8Ix1p3+teBfipM1pcg==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 13 2 600 20300101000000 20230101000000 40624 test-cds.example. 2O6dcFwAcuFReqBZmILkRfmYkvNpAFmIm7vsWmbbOiwmw5+iWqaD4/zp72ar/uZqxHekOO93Va/rl/uN182qBA==
;
`
var cdsZoneStringE string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 13 2 600 20300101000000 20230101000000 40624 test-cds.example. I/b+dkZLIhYUL4JdJZClw7SpE4gk4pHBtEv4a4DYiTdXi8xbESF4+vdj1og17+nn9RuEJaL7Usoms3xH0rW6aw==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 13 2 600 20300101000000 20230101000000 40624 test-cds.example. mOrmuqjzsZ5nZQqYHgoF8D7z6sQIYG0CGOOOgLsihr6yHmuEeNeoulN0pUIkBcxOg+mdx55OzyKoDWDphwwxgw==
test-cds.example.	600	IN	CDS	31714 13 2 f83329c878c3dd867b82607e049ef237ea13a84af60512aedaf604a8bad6ff4a
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDS	57655 15 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	RRSIG	CDS 13 2 600 20300101000000 20230101000000 40624 test-cds.example. 2w7noz9d4D0e8tKK4wn9uS25XL2C4RoiJMdTRKuT2XzKXoFHZwAmxb/Sx0lFA9y3JGWWxhH6Y8kyhz6evFbgcw==
test-cds.example.	600	IN	CDNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w==
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
test-cds.example.	600	IN	CDNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig==
test-cds.example.	600	IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU=
test-cds.example.	600	IN	RRSIG	CDNSKEY 13 2 600 20300101000000 20230101000000 40624 test-cds.example. oyDoPA+SGtpSPDie1B6ubcTA8Yu7XDIHMpOu5L2BofLO3DF61xdr9JEabiw1Z+mPWb6dKHpLu9SkOBddjxTYvg==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 13 2 600 20300101000000 20230101000000 40624 test-cds.example. Ey/4TuaYtlAofNnJi8I9cc90ULWxSQXb7r+sob/tVpXu1BlPAnKNWrBD5u0jsIRBvYI4xr4+MdOmgJivBmeM8A==
;
`
var cdsZoneStringF string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 15 2 600 20300101000000 20230101000000 57655 test-cds.example. j6bn9dy+oYaYwWLDCmIurWkGqDg14VOBynY+EiYzmZZh+cqSNAid2rk+GHH9UrEZv827/w11GTh5Vt456TDKAw==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. t7NcQCBcXD8v3zzQIHdKfkguRT15aP6GEvAO2FisvlAFNuQVYBIL+AkWIwa0H9sEzxHJRAgBhhI/pbHDlbKTBw==
test-cds.example.	600	IN	CDS	9187 16 2 aae96f383d93fe9b741a19c2051ce8f5f3a6f558bdc93b2575fde72ec7ddb188
test-cds.example.	600	IN	CDS	31714 13 2 f83329c878c3dd867b82607e049ef237ea13a84af60512aedaf604a8bad6ff4a
test-cds.example.	600	IN	CDS	40624 13 2 ae8619e146540d76e56adfb8e9f7dc2b0afec16eab0d6e058be63074345bd690
test-cds.example.	600	IN	CDS	47084 8 2 b16c32f3d15e4b6f4a8f91bc76c967c5b4f49ef49a1d9cdd340e0e32ed9c593c
test-cds.example.	600	IN	CDS	57655 15 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	CDS	57655 16 2 3b2d29df68df12910d4903b60f1181acb646d55046adabbd179ed4bc30d6b2eb
test-cds.example.	600	IN	RRSIG	CDS 15 2 600 20300101000000 20230101000000 57655 test-cds.example. cdScC2MSpfVo2rAiX4K2OESDpAmICwTtUE1a5ZlSGPLnl+jfDG+byyFOmGtNYytVJVpjgyQwmr6G/Ywx3IQrBA==
test-cds.example.	600	IN	CDNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w==
test-cds.example.	600	IN	CDNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0=
test-cds.example.	600	IN	CDNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig==
test-cds.example.	600	IN	CDNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU=
test-cds.example.	600	IN	RRSIG	CDNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. NQ3Gvcymqa/C70SITYj0Lxujlvufinooiyi8mm+6NiRsiRua1+4aZ0xjbcntIKISTvrYDuqvqMIoQd8H5ip7DA==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 15 2 600 20300101000000 20230101000000 57655 test-cds.example. USPIfNi31BiKE7HNYVpXVWdAnLPrnIQNAOJantegPsbOS6NNCv8kazF/rPC1zkwH0PGzHGIHgQO2PcZAFkP5Cg==
;
`

var cdsZoneStringG string = `
;; Zone: test-cds.example.
;
test-cds.example.	600	IN	SOA	test.example. mail.example. 1410271268 7200 3600 1209600 600
test-cds.example.	600	IN	RRSIG	SOA 8 2 600 20300101000000 20230101000000 38170 test-cds.example. beCmbakPpwwBj2Vv+oiSV8RMcHhtpHs94JXC+7reycAsnFvByTq4YSqG2RvU+8R9vvT3ATMyp0PO0KvQOzknPA==
test-cds.example.	600	IN	RRSIG	SOA 13 2 600 20300101000000 20230101000000 40624 test-cds.example. frQEAB60yqrzXR+zDzaZShGgPruGJ67SDsH3yg0J+KGM/Hhro7XSScYw1BJN88z4o42jrGazKYTylVjnaEEeCA==
;
test-cds.example.	600	IN	DNSKEY	256 3 8 AwEAAZtOaEH3qOAlEVzzWrmISpCNpg80NofRWBjoaCEZ7AYuK+Z2hleMQtpoa2Xal3eRYYZFGWxjrDCGTAMJ1YmRHMM= ;{id = 38170 (zsk), size = 512b}
test-cds.example.	600	IN	DNSKEY	256 3 13 RrtlPxwfrEv+EivQ2pjyjVJBO5yWowGnhFj477OWIPBJIg0MOwt7fJBhnFI/nAcYaAGnf+7hubX8EYwOnQlZ2w== ;{id = 40624 (zsk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 8 AwEAAceRxZ3KZQ61DK/+a77ibs1UWS2bJDQ2btkTsmPEVf4thv695D/vwYuQFfRBNerBChA8RxRSyAbLXEShxBP1Yq0= ;{id = 47084 (ksk), size = 512b}
test-cds.example.	600	IN	DNSKEY	257 3 13 EVdrgJMdnywXUwbCD0S+zb82KmnJ0ypUBrUkDEndgBLnGokWUvRokvcvgBbfig1dKfw5Kf4d7a3D9/2tIAtJig== ;{id = 31714 (ksk), size = 256b}
test-cds.example.	600	IN	DNSKEY	257 3 15 ZqAffyHTYiW0Lf/My4KmoTWC5MMoWgGxDjsxnwAQKLU= ;{id = 57655 (ksk), size = 256b}
test-cds.example.	600	IN	RRSIG	DNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. Dxs5P5ag64CvWcm6Cfq1I1b+gl7+M9wrI+cfAxbZBhPX09fgVYKf0wplLrWfbP6fHm/xShAcl+3sub27xLr0+w==
test-cds.example.	600	IN	RRSIG	DNSKEY 13 2 600 20300101000000 20230101000000 31714 test-cds.example. UDhetVggu+lT70PLJwL6Q0dW/JWPleb47yrlhF8LETSMIcBv8UFyAhvMdW+qbNcD+jFKuC2MZHDd+WTNBAFvnA==
test-cds.example.	600	IN	RRSIG	DNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. t7NcQCBcXD8v3zzQIHdKfkguRT15aP6GEvAO2FisvlAFNuQVYBIL+AkWIwa0H9sEzxHJRAgBhhI/pbHDlbKTBw==
test-cds.example.	600	IN	CDS	9187 16 2 aae96f383d93fe9b741a19c2051ce8f5f3a6f558bdc93b2575fde72ec7ddb188
test-cds.example.	600	IN	RRSIG	CDS 8 2 600 20300101000000 20230101000000 47084 test-cds.example. Ln5ssgGrOmNpjQ+YuVma2JSEXunwrJKWAodzyRyr4o/9M9dfOYD+HqsQhW3shSEuKbG0yZi5V6+V5sZx0sswbg==
test-cds.example.	600	IN	RRSIG	CDS 13 2 600 20300101000000 20230101000000 31714 test-cds.example. ncnVRWecBvhLSJsa5Ka8k13Phi6ls4mxdEBah1mwvCkEnbp4aeHpZB1EGhdSYgON7KV3fJ25JqVg63yFUz8pOQ==
test-cds.example.	600	IN	RRSIG	CDS 15 2 600 20300101000000 20230101000000 57655 test-cds.example. cjtDwwuCQVvT/FOVpptZdjSwpC1ZEk9Z+DShygFU0XCk2/xxTYIfqHWFuZ5GvGzfN1jI5pRv1jIBb2wYcM5wCg==
test-cds.example.	600	IN	CDNSKEY	257 3 16 ZCcER1ECBWYzM8Cimb14ftVrftWarohFmSsBGaAiRENMos7IGvTTQhs2ejOkbCkICtcauvoF2PEA
test-cds.example.	600	IN	RRSIG	CDNSKEY 8 2 600 20300101000000 20230101000000 47084 test-cds.example. HvgIrdtKGxSVB+lR7vC8RR8s8YMNR6mehSK8C5upMS3t5cLMHeCad/L8hrMVYcSQeP1++415PiF1fdG0rQEIBA==
test-cds.example.	600	IN	RRSIG	CDNSKEY 13 2 600 20300101000000 20230101000000 31714 test-cds.example. bbvzfXDy0aju6dNJrqWoFIDjF98FmdwQ/TcQHEAhQvILgWB30CdhWHR83TfE6Y1lrAXSmylfAUSSmsa229e9jw==
test-cds.example.	600	IN	RRSIG	CDNSKEY 15 2 600 20300101000000 20230101000000 57655 test-cds.example. FfZdm4hK4hHcXZY6JUN7hjOn/rXc6Tm1dAFNbwKzUaAmBaXi+K92jNNXoJMdkhne94K9PD3ud/xFPtkoXL+8DQ==
test-cds.example.	600	IN	NSEC	test-cds.example. SOA RRSIG NSEC DNSKEY CDS CDNSKEY 
test-cds.example.	600	IN	RRSIG	NSEC 8 2 600 20300101000000 20230101000000 38170 test-cds.example. kZ6KPukOpc10lmrlUzIJoJhg60DyGHSc1rGqzQLZTUsSrPOQMY7NY3RxBK20goMadedZ6HsAe/kJ76Gmr7AyEw==
test-cds.example.	600	IN	RRSIG	NSEC 13 2 600 20300101000000 20230101000000 40624 test-cds.example. baZYkOxDEF5+Zig2pWMN/SBNLuH+S5NHR/+loUWw4K6VW7K3Xsw0x+OK2iTKbKhC790yTCzzsrAur5XOdtLx9g==
;
`

func TestCheckCDS(t *testing.T) {
	cases := []struct {
		Zone     string
		Result
	}{
		{cdsZoneStringA, Result{1, 0}},
		{cdsZoneStringB, Result{0, 0}},
		{cdsZoneStringC, Result{0, 0}},
		{cdsZoneStringD, Result{0, 1}},
		{cdsZoneStringE, Result{0, 1}},
		{cdsZoneStringF, Result{0, 2}},
		{cdsZoneStringG, Result{1, 1}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		
		log.Debugf("TESTCASE %d",i)

		if r := checkCDS(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkCDS expected %d errors and %d warnings, found %d errors and %d warnings..", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}

func TestCheckCDSUsesAlgZero(t *testing.T) {

	cases := []struct {
		Zone     string
		Expected bool
	}{
		{cdsZoneString0, true},
		{cdsZoneString1, false},
		{cdsZoneString2, true},
		{cdsZoneString4, false},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)

		if b := cdsUsesAlgZero(cache, origin); b != c.Expected {
			t.Logf("Test case %d: cdsUsesAlgZero expected %v got %v", i, c.Expected, b)
			t.Fail()
		}
	}
}

func TestCheckCDSdelete(t *testing.T) {

	cases := []struct {
		Zone     string
		Result
	}{
		{cdsZoneString0, Result{0, 0}},
		{cdsZoneString3, Result{0, 1}},
		{cdsZoneString5, Result{0, 1}},
		{cdsZoneString6, Result{0, 1}},
		{cdsZoneString7, Result{0, 1}},
		{cdsZoneString8, Result{0, 1}},
		{cdsZoneString9, Result{0, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)

		if r := checkCDSdelete(cache[origin]["CDS"][0].(*dns.CDS)); r != c.Result {
			t.Logf("Test case %d: checkCDSdelete expected %d errors and %d warnings, found %d errors and %d warnings.", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}

func TestCheckCDSzero(t *testing.T) {
	cases := []struct {
		Zone     string
		Result
	}{
		{cdsZoneString0, Result{0, 0}},
		{cdsZoneString1, Result{0, 0}},
		{cdsZoneString2, Result{1, 6}},
		{cdsZoneString3, Result{0, 1}},
		{cdsZoneString5, Result{0, 1}},
		{cdsZoneString7, Result{0, 1}},
		{cdsZoneString8, Result{0, 1}},
		{cdsZoneString9, Result{0, 0}},
		{cdsZoneStringA, Result{1, 0}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)

		if r := checkCDSzero(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkCDSzero expected %d errors and %d warnings, found %d errors and %d warnings..", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}



func TestCheckCDSsignsDNSKEY(t *testing.T) {
	cases := []struct {
		Zone     string
		Result
	}{
		{cdsZoneStringB, Result{0, 0}},
		{cdsZoneStringC, Result{0, 0}},
		{cdsZoneStringD, Result{0, 0}},
		{cdsZoneStringE, Result{0, 0}},
		{cdsZoneStringF, Result{0, 2}},
		{cdsZoneStringG, Result{1, 1}},
	}

	for i, c := range cases {
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		
		log.Debugf("TESTCASE %d",i)

		if r := checkCDSsignsDNSKEY(cache, origin); r != c.Result {
			t.Logf("Test case %d: checkCDSsignsDNSKEY expected %d errors and %d warnings, found %d errors and %d warnings..", i, c.errors, c.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}
}
