package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

/*
This is a correct signed zone
*/
var nsec3Zone0 string = `
; test zone with no errors and no warnings
; iterations 0
; no salt
; no opt-out
;
glue.example.		300	IN	A	3.4.5.6
glue.example.		300	IN	AAAA	aced:0:0:0:0:0:0:cafe
test.			300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.			300	IN	RRSIG	SOA 13 1 300 20220501121328 20220401121328 11082 test. 6sx0tTDkGvg73Vfki9Zfgeia0zf6eB72Xuwy43i1qkEsTM9F85cw8D04g02AdqwCOUPOEORPzuojrmGe97DMcw==
test.			300	IN	NS	a.ns.test.
test.			300	IN	NS	ns.test.
test.			300	IN	RRSIG	NS 13 1 300 20220501121328 20220401121328 11082 test. bylPWxiaGszmlzh3CNZ1FoTeV6aa90KTfQNNI5kySw3DpMe/mPU7Aiha28doweUNEpzRhqx1dq5EryKqn6blqA==
test.			600	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw==
test.			600	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA==
test.			600	IN	RRSIG	DNSKEY 13 1 600 20220501121328 20220401121328 32290 test. lwe+nYztk03iebTtf+52W2qoWYNJGadQI6lg2WaiykhBSZrl6qeYGUZ0YhJd2nxs6VSuJlgJN1MPtlpNqJzAPw==
test.			300	IN	NSEC3PARAM	1 0 0 -
test.			300	IN	RRSIG	NSEC3PARAM 13 1 300 20220501121328 20220401121328 11082 test. iVFAPlruCJL3KrG3tb4NCgk4vRW2tH/BGQtlQWVALFCtpZBapzQ83GK4SHFCtiHPkkTsmF1Gxrvhz95Jfc5zxQ==
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	NSEC3	1 0 0 - 3Q3GTHSM77SIA151QI4I157DLE08VJOI TXT RRSIG ; domain4.test.
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. oSV+mcTYoLbdz4ccMMm1v8rLirqiNQCD+Mlu3bW8QH4IMtYEgIBy8etIdGBj05Agwz/D62EI5WXM86jjPl+BKw==
3Q3GTHSM77SIA151QI4I157DLE08VJOI.test.	14400	IN	NSEC3	1 0 0 - 5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV A RRSIG ; brokensig.test.
3Q3GTHSM77SIA151QI4I157DLE08VJOI.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. ukEJyPN06XRx+3GOabGjkBYf49kJr1erFyd3TMOtoehgtam+622osULuOCFraHoZ8+uRjHDW4mN5mRdDpJ3Oyg==
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	NSEC3	1 0 0 - FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19 NS SOA RRSIG DNSKEY NSEC3PARAM ; test.
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. czq4bKZAr+6dTLMAOAecrxockaIAImxsKhnX+pWY4m2gDdJzoaWpMROr+JsEUhok3jgypIzcCFZK/aheOJB9aA==
brokensig.test.		300	IN	A	10.0.0.0
brokensig.test.		300	IN	RRSIG	A 13 2 300 20220501121328 20220401121328 11082 test. pMHPMPfzNKFIqn1QAhKHNM6JPuAvIGBqNcvYm6ZjsyZ4NWQyxZL2QkEDKfdkHRbLTcLRgGcpoTF751yrhQ7PdA==
domain.test.		300	IN	NS	noglue.example.
domain.test.		300	IN	DS	16158 13 2 ACF37AEF08E964BA41FA068638CB30074CCDE5C572CA5031F8A812250CE300E7
domain.test.		300	IN	RRSIG	DS 13 2 300 20220501121328 20220401121328 11082 test. fvRZcJqBRQ+s03Mrjo27fNpnjGkZOVDotHCd9T/LE/gaFyjC1J0FDaoAbd9WC7MVsZ5tqZunRcCtCXTnyoIGSw==
domain2.test.		300	IN	NS	glue.example.
domain3.test.		300	IN	NS	ns.domain3.test.
domain3.test.		300	IN	NS	domain3.test.
domain3.test.		300	IN	A	4.5.6.7
ns.domain3.test.	300	IN	AAAA	dead:0:0:0:0:0:0:beef
domain4.test.		300	IN	TXT	"blahhblahhblahh"
domain4.test.		300	IN	RRSIG	TXT 13 2 300 20220501121328 20220401121328 11082 test. ArNUkxaSVZQp48osXPP1WQ5yl8dtXVtPRlgis1M/2qOWxM73UN3FbPTNBzsff7cSUR/puANUVnsN91+er+l32A==
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	NSEC3	1 0 0 - GLF8EI9MSLNHUED8AQ8H7IF8722H27LT A AAAA RRSIG ; ns.test.
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. Am27B1WP5o7V9Y0GiJy8EtcUtzasGQcVTyi7+9v8plEMPuMX8Unlf173iQgYU90bKdAH6jG9TfYbmbgbdbZEng==
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	NSEC3	1 0 0 - LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O NS DS RRSIG ; domain.test.
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. mQ6BPhFKqFpxaN/xflx9WlNEplQubwnMdUTuUtG+3EeTZqDjnfKXcWsBdgP4OsHooeoyZUEoiGkZH8ibNa9zRg==
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	NSEC3	1 0 0 - O6C4PLP692R4BJKG4JV6I6O9J0ASKC3V A AAAA RRSIG ; a.ns.test.
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. 1HZCxRe5Qti18x9SYaHI/AIB3Y9yFch4POS19sYXedYvcdnV1hgXmeGaxyLXHvZveIMsgHbvqauzbF4FC4Ef7A==
ns.test.		300	IN	A	1.2.3.4
ns.test.		300	IN	RRSIG	A 13 2 300 20220501121328 20220401121328 11082 test. 9yYBqu3HrpNpXDHzg+6GC4+YcNra9uGTrRMZDkV9P3N3+StzQK+VQdqf+AEshzo1fVxpA5aSmQVM7mIPJuSNJg==
ns.test.		300	IN	AAAA	cafe:0:0:0:0:0:0:bad
ns.test.		300	IN	RRSIG	AAAA 13 2 300 20220501121328 20220401121328 11082 test. stKj/2+mu1ijjCfPfFiuc8PRpblB9pDJV9rQ8GAPkiuc2DXYdp5/Lari/1K7jSxqRJVEU4w124rzBlV/MG0ckw==
a.ns.test.		300	IN	A	2.3.4.5
a.ns.test.		300	IN	RRSIG	A 13 3 300 20220501121328 20220401121328 11082 test. fVuJ28JFZowmTVMGxO67bCJybnuwH0lwPitdg68nxyawuhYv/DQTibLQ3yHNR9EyFEZsE0SGOWQphCVW3/zv9A==
a.ns.test.		300	IN	AAAA	bad:0:0:0:0:0:0:cafe
a.ns.test.		300	IN	RRSIG	AAAA 13 3 300 20220501121328 20220401121328 11082 test. HWmXT7hxT8wCNb7OGqTshNMNfY+/4MMzhU9MJ7Q0agnyDSlB0NzgXllH2t2c741k4/YJUY1aB4Q9KC8yN6OSOQ==
O6C4PLP692R4BJKG4JV6I6O9J0ASKC3V.test.	14400	IN	NSEC3	1 0 0 - P8MH4V9JNCF7I98LKRPB81N79DHOQL5K NS ; domain3.test.
O6C4PLP692R4BJKG4JV6I6O9J0ASKC3V.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. 3C4g/3dPos/3WGscap2Bf8mo/036ydCbTL9ES2Uhh/5pGt1zF/4B/O8pCYAz2wy9m5XS+LuJYGqCrZC/w2mIcA==
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	NSEC3	1 0 0 - 1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B NS ; domain2.test.
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. k7DYVNqQEnRdhgV7YBycJbyYvxm3Da51jtFpWiG0e5KERuumbnmKVqhweVZsGNxx7xFXf0rg9XQO9rMjiCvAgA==
`

/*
Same zone as above but
- one nsec3 label has been deleted and the chain fixed
- one label deleted and chain not fixed
- chain is in wrong order in another place
- duplicated one NSEC3 label
*/
var nsec3Zone1 string = `
; test zone with no errors and no warnings
; iterations 0
; no salt
; no opt-out
;
glue.example.		300	IN	A	3.4.5.6
glue.example.		300	IN	AAAA	aced:0:0:0:0:0:0:cafe
test.			300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.			300	IN	RRSIG	SOA 13 1 300 20220501121328 20220401121328 11082 test. 6sx0tTDkGvg73Vfki9Zfgeia0zf6eB72Xuwy43i1qkEsTM9F85cw8D04g02AdqwCOUPOEORPzuojrmGe97DMcw==
test.			300	IN	NS	a.ns.test.
test.			300	IN	NS	ns.test.
test.			300	IN	RRSIG	NS 13 1 300 20220501121328 20220401121328 11082 test. bylPWxiaGszmlzh3CNZ1FoTeV6aa90KTfQNNI5kySw3DpMe/mPU7Aiha28doweUNEpzRhqx1dq5EryKqn6blqA==
test.			600	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw==
test.			600	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA==
test.			600	IN	RRSIG	DNSKEY 13 1 600 20220501121328 20220401121328 32290 test. lwe+nYztk03iebTtf+52W2qoWYNJGadQI6lg2WaiykhBSZrl6qeYGUZ0YhJd2nxs6VSuJlgJN1MPtlpNqJzAPw==
test.			300	IN	NSEC3PARAM	1 0 0 -
test.			300	IN	RRSIG	NSEC3PARAM 13 1 300 20220501121328 20220401121328 11082 test. iVFAPlruCJL3KrG3tb4NCgk4vRW2tH/BGQtlQWVALFCtpZBapzQ83GK4SHFCtiHPkkTsmF1Gxrvhz95Jfc5zxQ==
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	NSEC3	1 0 0 - 3Q3GTHSM77SIA151QI4I157DLE08VJOI TXT RRSIG ; domain4.test.
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	NSEC3	1 0 0 - 3Q3GTHSM77SIA151QI4I157DLE08VJOI TXT A RRSIG ; domain4.test.
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. oSV+mcTYoLbdz4ccMMm1v8rLirqiNQCD+Mlu3bW8QH4IMtYEgIBy8etIdGBj05Agwz/D62EI5WXM86jjPl+BKw==
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	NSEC3	1 0 0 - GLF8EI9MSLNHUED8AQ8H7IF8722H27LT NS SOA RRSIG DNSKEY NSEC3PARAM ; test.
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. czq4bKZAr+6dTLMAOAecrxockaIAImxsKhnX+pWY4m2gDdJzoaWpMROr+JsEUhok3jgypIzcCFZK/aheOJB9aA==
brokensig.test.		300	IN	A	10.0.0.0
brokensig.test.		300	IN	RRSIG	A 13 2 300 20220501121328 20220401121328 11082 test. pMHPMPfzNKFIqn1QAhKHNM6JPuAvIGBqNcvYm6ZjsyZ4NWQyxZL2QkEDKfdkHRbLTcLRgGcpoTF751yrhQ7PdA==
domain.test.		300	IN	NS	noglue.example.
domain.test.		300	IN	DS	16158 13 2 ACF37AEF08E964BA41FA068638CB30074CCDE5C572CA5031F8A812250CE300E7
domain.test.		300	IN	RRSIG	DS 13 2 300 20220501121328 20220401121328 11082 test. fvRZcJqBRQ+s03Mrjo27fNpnjGkZOVDotHCd9T/LE/gaFyjC1J0FDaoAbd9WC7MVsZ5tqZunRcCtCXTnyoIGSw==
domain2.test.		300	IN	NS	glue.example.
domain3.test.		300	IN	NS	ns.domain3.test.
domain3.test.		300	IN	NS	domain3.test.
domain3.test.		300	IN	A	4.5.6.7
ns.domain3.test.	300	IN	AAAA	dead:0:0:0:0:0:0:beef
domain4.test.		300	IN	TXT	"blahhblahhblahh"
domain4.test.		300	IN	RRSIG	TXT 13 2 300 20220501121328 20220401121328 11082 test. ArNUkxaSVZQp48osXPP1WQ5yl8dtXVtPRlgis1M/2qOWxM73UN3FbPTNBzsff7cSUR/puANUVnsN91+er+l32A==
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	NSEC3	1 0 0 - LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O A AAAA RRSIG ; ns.test.
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. Am27B1WP5o7V9Y0GiJy8EtcUtzasGQcVTyi7+9v8plEMPuMX8Unlf173iQgYU90bKdAH6jG9TfYbmbgbdbZEng==
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	NSEC3	1 0 0 - FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19 NS DS RRSIG ; domain.test.
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. mQ6BPhFKqFpxaN/xflx9WlNEplQubwnMdUTuUtG+3EeTZqDjnfKXcWsBdgP4OsHooeoyZUEoiGkZH8ibNa9zRg==
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	NSEC3	1 0 0 - P8MH4V9JNCF7I98LKRPB81N79DHOQL5K A AAAA RRSIG ; a.ns.test.
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. 1HZCxRe5Qti18x9SYaHI/AIB3Y9yFch4POS19sYXedYvcdnV1hgXmeGaxyLXHvZveIMsgHbvqauzbF4FC4Ef7A==
ns.test.		300	IN	A	1.2.3.4
ns.test.		300	IN	RRSIG	A 13 2 300 20220501121328 20220401121328 11082 test. 9yYBqu3HrpNpXDHzg+6GC4+YcNra9uGTrRMZDkV9P3N3+StzQK+VQdqf+AEshzo1fVxpA5aSmQVM7mIPJuSNJg==
ns.test.		300	IN	AAAA	cafe:0:0:0:0:0:0:bad
ns.test.		300	IN	RRSIG	AAAA 13 2 300 20220501121328 20220401121328 11082 test. stKj/2+mu1ijjCfPfFiuc8PRpblB9pDJV9rQ8GAPkiuc2DXYdp5/Lari/1K7jSxqRJVEU4w124rzBlV/MG0ckw==
a.ns.test.		300	IN	A	2.3.4.5
a.ns.test.		300	IN	RRSIG	A 13 3 300 20220501121328 20220401121328 11082 test. fVuJ28JFZowmTVMGxO67bCJybnuwH0lwPitdg68nxyawuhYv/DQTibLQ3yHNR9EyFEZsE0SGOWQphCVW3/zv9A==
a.ns.test.		300	IN	AAAA	bad:0:0:0:0:0:0:cafe
a.ns.test.		300	IN	RRSIG	AAAA 13 3 300 20220501121328 20220401121328 11082 test. HWmXT7hxT8wCNb7OGqTshNMNfY+/4MMzhU9MJ7Q0agnyDSlB0NzgXllH2t2c741k4/YJUY1aB4Q9KC8yN6OSOQ==
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	NSEC3	1 0 0 - 1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B NS ; domain2.test.
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. k7DYVNqQEnRdhgV7YBycJbyYvxm3Da51jtFpWiG0e5KERuumbnmKVqhweVZsGNxx7xFXf0rg9XQO9rMjiCvAgA==
`

/*
Correct signed zone with ot out
*/
var nsec3ZoneOptOut0 string = `
; test zone with no errors and no warnings
; iterations 0
; no salt
; opt-out
;
glue.example.		300	IN	A	3.4.5.6
glue.example.		300	IN	AAAA	aced:0:0:0:0:0:0:cafe
test.			300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.			300	IN	RRSIG	SOA 13 1 300 20220501121558 20220401121558 11082 test. g/fTeQhdTUwS2m63TClb8i37OC1htCWzwJZyDgPPNh1uPy8Zm/dS8UXRLzaTMMHdPOLELdAeYmRRYJAmjwTsGg==
test.			300	IN	NS	a.ns.test.
test.			300	IN	NS	ns.test.
test.			300	IN	RRSIG	NS 13 1 300 20220501121558 20220401121558 11082 test. q5rkuuk91nHdTN87hH7BdiEI9AcRUvzp/fwuaOM+vHHYcLdevUSCQpQxA3ybQ9clW7TFLkkDuifWX7N033Jvpg==
test.			600	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw==
test.			600	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA==
test.			600	IN	RRSIG	DNSKEY 13 1 600 20220501121558 20220401121558 32290 test. XcSKetL7GNkTyMWD7Vw1iXzpsGGeAGaW4yVbM1Xwv7Q8WZFIE3fy5pLq27pReBCkwW9+vFEKP/n4wcy0Tx7okw==
test.			300	IN	NSEC3PARAM	1 0 0 -
test.			300	IN	RRSIG	NSEC3PARAM 13 1 300 20220501121558 20220401121558 11082 test. NDzgTb1/vs/KgG/Ykv76B2xbzUxZw6HCGaxAPGKwn92n7WguJhcoK7pLGwT80PlXGA6skTn17tp7ZHHNLvTdKA==
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	NSEC3	1 1 0 - 3Q3GTHSM77SIA151QI4I157DLE08VJOI TXT RRSIG ; domain4.test.
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. 7X5siSZyN9Q2Nu28w5ZXtsLf7gf/rVB8Kaymzwz4X3fvgbFELe4UAYMQpONE+XM+UHJpakfLDzorXdkF3/mtzQ==
3Q3GTHSM77SIA151QI4I157DLE08VJOI.test.	14400	IN	NSEC3	1 1 0 - 5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV A RRSIG ; brokensig.test.
3Q3GTHSM77SIA151QI4I157DLE08VJOI.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. abbTutPDhnWwDiznLUUD33FmSj3zUi9sCdMTdl+v1R9cQ1L9jy+pQwD6H4lTOK1DeVveh0GjMRQQANyOR+Y9tw==
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	NSEC3	1 1 0 - FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19 NS SOA RRSIG DNSKEY NSEC3PARAM ; test.
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. Zd4QK8XjgvQLhnPbaDLr5TmC0w+Z57IwvBg/3WG6wcVh1koBsVviXWzG3myeoIhu+dY0E5ElhZcUd++f/KhZNw==
brokensig.test.		300	IN	A	10.0.0.0
brokensig.test.		300	IN	RRSIG	A 13 2 300 20220501121558 20220401121558 11082 test. YMeMqLcYH0vkbRA5wtbOyltIlKaMngQat4ZP5Qx4l6BHHxaRLY4fhH2Y6sAm/RIdkYiXKYioCeWOP4yIWtEMRg==
domain.test.		300	IN	NS	noglue.example.
domain.test.		300	IN	DS	16158 13 2 ACF37AEF08E964BA41FA068638CB30074CCDE5C572CA5031F8A812250CE300E7
domain.test.		300	IN	RRSIG	DS 13 2 300 20220501121558 20220401121558 11082 test. ZA4CfshoiH+fKQUBbODUJxvhFc6bCn4+a0zSwRakte63lUCVRzPwJ0z1/VeWKBVTAUmMBIBRfM0jIBr26rg8Gg==
domain2.test.		300	IN	NS	glue.example.
domain3.test.		300	IN	NS	ns.domain3.test.
domain3.test.		300	IN	NS	domain3.test.
domain3.test.		300	IN	A	4.5.6.7
ns.domain3.test.	300	IN	AAAA	dead:0:0:0:0:0:0:beef
domain4.test.		300	IN	TXT	"blahhblahhblahh"
domain4.test.		300	IN	RRSIG	TXT 13 2 300 20220501121558 20220401121558 11082 test. nuJ1MD6DhC0883Tl3pCjr/6hZGtRFmVTCiafNZQC0PD8Ya8lqA6Dx2yCW5RU6WBMkU8O89SK9swrrAXEaJG/LQ==
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	NSEC3	1 1 0 - GLF8EI9MSLNHUED8AQ8H7IF8722H27LT A AAAA RRSIG ; ns.test.
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. Fe99Gk1Cv378i7YGT91I2K8ovPIPrIRZ/gB4sR2XPp2KbteVzZ8WtTzMiJJjSTcKsqzaBZ8YsfUbkJqoY+wTpA==
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	NSEC3	1 1 0 - LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O NS DS RRSIG ; domain.test.
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. PGzYonGqnvOEmB5lJGz4SbdLszsTZ6eLQm4/jR3dQXsuiwivkEH/iaYsl2ecY/J8GeVGJrIrmWbeTKGKS0CXAA==
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	NSEC3	1 1 0 - 1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B A AAAA RRSIG ; a.ns.test.
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. U6hdh9ir9Z002/axEeRYiaFZHC066vYYMCFboYwTbXfl3zfXxCHl7OsPYU4P9pNZKiNj1ZzG+6Ps+8vXfKjXLw==
ns.test.		300	IN	A	1.2.3.4
ns.test.		300	IN	RRSIG	A 13 2 300 20220501121558 20220401121558 11082 test. OFakL0PO3Ar8GixENPlv2NKlmb1DWnrW6hG9YTO/8fURnN+0ucFrCqZcR7ixf5uW7D8h/dN6RkJ6zxi7LBkUyQ==
ns.test.		300	IN	AAAA	cafe:0:0:0:0:0:0:bad
ns.test.		300	IN	RRSIG	AAAA 13 2 300 20220501121558 20220401121558 11082 test. 7xzaG8RtrABfCBS2lZaeKntzf+5yYycXAz7Oyh/eITawUp5nwbxjtefoG3zUCYk9yxyGzFs7XKLbjBI79y2rjA==
a.ns.test.		300	IN	A	2.3.4.5
a.ns.test.		300	IN	RRSIG	A 13 3 300 20220501121558 20220401121558 11082 test. WxWP7vX9tfIMhtKF42Ja2c2EqXOg3b2Sl1q78mteIIPwn0R8HwLpfn0nNirsIKSjYW2M+HObTl3Aq3K5zZA6JA==
a.ns.test.		300	IN	AAAA	bad:0:0:0:0:0:0:cafe
a.ns.test.		300	IN	RRSIG	AAAA 13 3 300 20220501121558 20220401121558 11082 test. U3b5wqjKSi8fEjPMNRopFuHPOqiR+o/7QqcoMKCRpS3An0tl55pdo129MII62Kwbi5iSFIKbfh+DEpZKTplGuw==
`

/*
Same zone as above but
- one label deleted
- one label points to wrong next secure
- one extra label
*/
var nsec3ZoneOptOut1 string = `
; test zone with no errors and no warnings
; iterations 0
; no salt
; opt-out
;
glue.example.		300	IN	A	3.4.5.6
glue.example.		300	IN	AAAA	aced:0:0:0:0:0:0:cafe
test.			300	IN	SOA	master.ns.test. mail.nic.test. 12345 1800 3600 7200 14400
test.			300	IN	RRSIG	SOA 13 1 300 20220501121558 20220401121558 11082 test. g/fTeQhdTUwS2m63TClb8i37OC1htCWzwJZyDgPPNh1uPy8Zm/dS8UXRLzaTMMHdPOLELdAeYmRRYJAmjwTsGg==
test.			300	IN	NS	a.ns.test.
test.			300	IN	NS	ns.test.
test.			300	IN	RRSIG	NS 13 1 300 20220501121558 20220401121558 11082 test. q5rkuuk91nHdTN87hH7BdiEI9AcRUvzp/fwuaOM+vHHYcLdevUSCQpQxA3ybQ9clW7TFLkkDuifWX7N033Jvpg==
test.			600	IN	DNSKEY	256 3 13 IcKbK9FMlIsJSzC2o53aPsWGELPvWpWbKnZ2zJiID6nY6TFpMy31z60TNNbbfgJsGloL+zrOZwuV+h6darXNUw==
test.			600	IN	DNSKEY	257 3 13 t2LVP+yZIiE9JPorgUdZNesR9fYl+715hSjItwxqzxgdH4ApBhqpA/lu/xF9ADmtUAZeU1PbIHXtbwP2HMOyoA==
test.			600	IN	RRSIG	DNSKEY 13 1 600 20220501121558 20220401121558 32290 test. XcSKetL7GNkTyMWD7Vw1iXzpsGGeAGaW4yVbM1Xwv7Q8WZFIE3fy5pLq27pReBCkwW9+vFEKP/n4wcy0Tx7okw==
test.			300	IN	NSEC3PARAM	1 0 0 -
test.			300	IN	RRSIG	NSEC3PARAM 13 1 300 20220501121558 20220401121558 11082 test. NDzgTb1/vs/KgG/Ykv76B2xbzUxZw6HCGaxAPGKwn92n7WguJhcoK7pLGwT80PlXGA6skTn17tp7ZHHNLvTdKA==
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	NSEC3	1 1 0 - 3Q3GTHSM77SIA151QI4I157DLE08VJOI TXT RRSIG ; domain4.test.
1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. 7X5siSZyN9Q2Nu28w5ZXtsLf7gf/rVB8Kaymzwz4X3fvgbFELe4UAYMQpONE+XM+UHJpakfLDzorXdkF3/mtzQ==
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	NSEC3	1 1 0 - FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19 NS SOA RRSIG DNSKEY NSEC3PARAM ; test.
5U2I2H5CO0EBB4R9HIPBKU7PEA6GGPSV.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. Zd4QK8XjgvQLhnPbaDLr5TmC0w+Z57IwvBg/3WG6wcVh1koBsVviXWzG3myeoIhu+dY0E5ElhZcUd++f/KhZNw==
brokensig.test.		300	IN	A	10.0.0.0
brokensig.test.		300	IN	RRSIG	A 13 2 300 20220501121558 20220401121558 11082 test. YMeMqLcYH0vkbRA5wtbOyltIlKaMngQat4ZP5Qx4l6BHHxaRLY4fhH2Y6sAm/RIdkYiXKYioCeWOP4yIWtEMRg==
domain.test.		300	IN	NS	noglue.example.
domain.test.		300	IN	DS	16158 13 2 ACF37AEF08E964BA41FA068638CB30074CCDE5C572CA5031F8A812250CE300E7
domain.test.		300	IN	RRSIG	DS 13 2 300 20220501121558 20220401121558 11082 test. ZA4CfshoiH+fKQUBbODUJxvhFc6bCn4+a0zSwRakte63lUCVRzPwJ0z1/VeWKBVTAUmMBIBRfM0jIBr26rg8Gg==
domain2.test.		300	IN	NS	glue.example.
domain3.test.		300	IN	NS	ns.domain3.test.
domain3.test.		300	IN	NS	domain3.test.
domain3.test.		300	IN	A	4.5.6.7
ns.domain3.test.	300	IN	AAAA	dead:0:0:0:0:0:0:beef
domain4.test.		300	IN	TXT	"blahhblahhblahh"
domain4.test.		300	IN	RRSIG	TXT 13 2 300 20220501121558 20220401121558 11082 test. nuJ1MD6DhC0883Tl3pCjr/6hZGtRFmVTCiafNZQC0PD8Ya8lqA6Dx2yCW5RU6WBMkU8O89SK9swrrAXEaJG/LQ==
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	NSEC3	1 1 0 - LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O A AAAA RRSIG ; ns.test.
FJ6TVCIL6NJKNSNGSJD7IT4C3TOPDS19.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. Fe99Gk1Cv378i7YGT91I2K8ovPIPrIRZ/gB4sR2XPp2KbteVzZ8WtTzMiJJjSTcKsqzaBZ8YsfUbkJqoY+wTpA==
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	NSEC3	1 1 0 - LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O NS DS RRSIG ; domain.test.
GLF8EI9MSLNHUED8AQ8H7IF8722H27LT.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. PGzYonGqnvOEmB5lJGz4SbdLszsTZ6eLQm4/jR3dQXsuiwivkEH/iaYsl2ecY/J8GeVGJrIrmWbeTKGKS0CXAA==
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	NSEC3	1 1 0 - P8MH4V9JNCF7I98LKRPB81N79DHOQL5K A AAAA RRSIG ; a.ns.test.
LJKPGIFJS9K7DN5L5LMFPLHTBOGTN76O.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121558 20220401121558 11082 test. U6hdh9ir9Z002/axEeRYiaFZHC066vYYMCFboYwTbXfl3zfXxCHl7OsPYU4P9pNZKiNj1ZzG+6Ps+8vXfKjXLw==
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	NSEC3	1 0 0 - 1F7C69DK1QN74JDN4H39DPKQ2R9Q6F2B NS ; domain2.test.
P8MH4V9JNCF7I98LKRPB81N79DHOQL5K.test.	14400	IN	RRSIG	NSEC3 13 2 14400 20220501121328 20220401121328 11082 test. k7DYVNqQEnRdhgV7YBycJbyYvxm3Da51jtFpWiG0e5KERuumbnmKVqhweVZsGNxx7xFXf0rg9XQO9rMjiCvAgA==
ns.test.		300	IN	A	1.2.3.4
ns.test.		300	IN	RRSIG	A 13 2 300 20220501121558 20220401121558 11082 test. OFakL0PO3Ar8GixENPlv2NKlmb1DWnrW6hG9YTO/8fURnN+0ucFrCqZcR7ixf5uW7D8h/dN6RkJ6zxi7LBkUyQ==
ns.test.		300	IN	AAAA	cafe:0:0:0:0:0:0:bad
ns.test.		300	IN	RRSIG	AAAA 13 2 300 20220501121558 20220401121558 11082 test. 7xzaG8RtrABfCBS2lZaeKntzf+5yYycXAz7Oyh/eITawUp5nwbxjtefoG3zUCYk9yxyGzFs7XKLbjBI79y2rjA==
a.ns.test.		300	IN	A	2.3.4.5
a.ns.test.		300	IN	RRSIG	A 13 3 300 20220501121558 20220401121558 11082 test. WxWP7vX9tfIMhtKF42Ja2c2EqXOg3b2Sl1q78mteIIPwn0R8HwLpfn0nNirsIKSjYW2M+HObTl3Aq3K5zZA6JA==
a.ns.test.		300	IN	AAAA	bad:0:0:0:0:0:0:cafe
a.ns.test.		300	IN	RRSIG	AAAA 13 3 300 20220501121558 20220401121558 11082 test. U3b5wqjKSi8fEjPMNRopFuHPOqiR+o/7QqcoMKCRpS3An0tl55pdo129MII62Kwbi5iSFIKbfh+DEpZKTplGuw==
`

func TestCheckNSEC3chain(t *testing.T) {
	cases := []struct {
		Zone             string
		OptOutOK         bool
		ExpectedErrors   uint32
		ExpectedWarnings uint32
	}{
		{nsec3Zone0, false, 0, 0},
		{nsec3Zone0, true, 0, 0},
		{nsec3Zone1, false, 4, 0},
		{nsec3Zone1, true, 4, 0},
		{nsec3ZoneOptOut0, false, 0, 6},
		{nsec3ZoneOptOut0, true, 0, 0},
		{nsec3ZoneOptOut1, false, 2, 5},
		{nsec3ZoneOptOut1, true, 2, 0},
	}

	viper.Set("verbose", 2)
	for i, c := range cases {
		viper.Set(NSEC3_OPTOUTOK, c.OptOutOK)
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)
		if r := checkNSEC3chain(cache, origin); r.errors != c.ExpectedErrors || r.warnings != c.ExpectedWarnings {
			t.Logf("Test case %d: checkNSEC3chain expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.ExpectedErrors, c.ExpectedWarnings, r.errors, r.warnings)
			t.Fail()
		}
	}
	viper.Reset()
}

func TestCheckNSEC3labels(t *testing.T) {
	cases := []struct {
		Zone     string
		Expected Result
	}{
		{nsec3Zone0, Result{0, 0}},
		{nsec3Zone1, Result{1, 0}},
		{nsec3ZoneOptOut0, Result{0, 0}},
		{nsec3ZoneOptOut1, Result{10, 10}},
	}

	viper.Set("verbose", 1)
	for i, c := range cases {
		fmt.Println("TEST CASE ", i)
		myReader := strings.NewReader(c.Zone)
		origin, cache := readZonefile(myReader)

		if r := checkNSEC3Labels(cache, origin); r != c.Expected {
			t.Logf("Test case %d: checkNSEC3Labels expected %d errors and %d warnings, found %d errors and %d warnings.\n.", i, c.Expected.errors, c.Expected.warnings, r.errors, r.warnings)
			t.Fail()
		}
	}

}

func TestCheckNSEC3rr(t *testing.T) {
	cases := []struct {
		Nsec3            *dns.NSEC3
		ExpectedWarnings uint32
		ExpectedErrors   uint32
	}{
		{NewRR("test. NSEC3 1 0  0 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 0, 0},
		{NewRR("test. NSEC3 2 0  0 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 0, 1},
		{NewRR("test. NSEC3 1 1  0 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 1, 0},
		{NewRR("test. NSEC3 1 2  0 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 0, 1},
		{NewRR("test. NSEC3 1 0  1 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 1, 0},
		{NewRR("test. NSEC3 1 0 11 -    2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 0, 1},
		{NewRR("test. NSEC3 1 0  0 AABB 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 1, 0},
		{NewRR("test. NSEC3 2 5 99 CCDD 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG").(*dns.NSEC3), 2, 3},
	}

	viper.Set("verbose", 2)
	for i, c := range cases {
		r := checkNSEC3rr(c.Nsec3)
		if r.errors != c.ExpectedErrors {
			t.Logf("Test case %d: checkNSEC3rr expected %d errors found %d errors.\n.", i, c.ExpectedErrors, r.errors)
			t.Fail()
		}
		if r.warnings != c.ExpectedWarnings {
			t.Logf("Test case %d: checkNSEC3rr expected %d warnings found %d warnings.\n.", i, c.ExpectedWarnings, r.warnings)
			t.Fail()
		}
	}

}
