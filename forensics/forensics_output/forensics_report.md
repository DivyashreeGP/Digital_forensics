# Digital Forensics Report — Combined Case Study (TShark Analysis)

## Executive Summary
An automated analysis was performed on captured network traffic exported from the supplied PCAP using TShark. The goals were to identify credential leakage, suspicious DNS activity (possible C2/beaconing), and to profile network traffic for anomalies.

## Evidence & Files Analyzed
- PCAP file: `case_study_large.pcap` (if available)
- HTTP export: `http_requests.tsv` — 197404 records
- Authorization headers export: `auth_headers.tsv` — 25000 records
- DNS export: `dns_queries.tsv` — 175000 records
- Timeline export: `timeline.tsv` — 530000 records

## Key Findings (high level)
- Total HTTP requests: **197404**
- Total DNS queries: **175000**
- Total captured packets (timeline records): **530000**
- Found **25000** HTTP Authorization headers. Several decode to plaintext credentials. See details below.
- Evidence of C2-like activity was detected (DNS beaconing and/or HTTP callbacks). See C2 section.

## Visualizations
### Packet timeline
![Timeline](timeline.png)

### Packet size distribution
![Packet size histogram](packet_size_hist.png)

### Protocol distribution (estimated)
![Protocol distribution](protocol_dist.png)

### Top DNS queries
![DNS frequency](dns_freq.png)

### Top HTTP hosts
![HTTP hosts](http_hosts.png)

### Decoded Authorization summary
![Auth decoded](auth_decoded.png)

### Top talkers by bytes
![Top talkers](top_talkers.png)

### Top source->destination flows (subset)
![Flows matrix](flows_matrix.png)

### Suspicious DNS (C2-like) hits
![C2 DNS](c2_dns.png)

### Suspicious HTTP callback hosts
![C2 HTTP](c2_http.png)

## Detailed Findings
### Credentials extracted from HTTP Authorization headers

| Time | Source IP | Destination IP | Host | Decoded credentials |
| --- | --- | --- | --- | --- |
| 2025-11-16T13:26:34.201486 | 192.168.10.65 | 93.184.216.34 | leak.example | `user22671:pass22671` |
| 2025-11-16T13:26:34.202266 | 192.168.10.34 | 93.184.216.34 | leak.example | `user24926:pass24926` |
| 2025-11-16T13:26:34.202776 | 192.168.10.23 | 93.184.216.34 | leak.example | `user21105:pass21105` |
| 2025-11-16T13:26:34.203826 | 192.168.10.131 | 93.184.216.34 | leak.example | `user24261:pass24261` |
| 2025-11-16T13:26:34.204036 | 192.168.10.67 | 93.184.216.34 | leak.example | `user19625:pass19625` |
| 2025-11-16T13:26:34.204606 | 192.168.10.89 | 93.184.216.34 | leak.example | `user3137:pass3137` |
| 2025-11-16T13:26:34.204996 | 192.168.10.117 | 93.184.216.34 | leak.example | `user16627:pass16627` |
| 2025-11-16T13:26:34.205626 | 192.168.10.31 | 93.184.216.34 | leak.example | `user12223:pass12223` |
| 2025-11-16T13:26:34.207816 | 192.168.10.230 | 93.184.216.34 | leak.example | `user13184:pass13184` |
| 2025-11-16T13:26:34.208956 | 192.168.10.71 | 93.184.216.34 | leak.example | `user2611:pass2611` |
| 2025-11-16T13:26:34.209106 | 192.168.10.45 | 93.184.216.34 | leak.example | `user8173:pass8173` |
| 2025-11-16T13:26:34.210606 | 192.168.10.242 | 93.184.216.34 | leak.example | `user19546:pass19546` |
| 2025-11-16T13:26:34.212166 | 192.168.10.191 | 93.184.216.34 | leak.example | `user21781:pass21781` |
| 2025-11-16T13:26:34.212376 | 192.168.10.3 | 93.184.216.34 | leak.example | `user20831:pass20831` |
| 2025-11-16T13:26:34.212616 | 192.168.10.247 | 93.184.216.34 | leak.example | `user23107:pass23107` |
| 2025-11-16T13:26:34.212796 | 192.168.10.187 | 93.184.216.34 | leak.example | `user949:pass949` |
| 2025-11-16T13:26:34.213936 | 192.168.10.246 | 93.184.216.34 | leak.example | `user246:pass246` |
| 2025-11-16T13:26:34.214086 | 192.168.10.161 | 93.184.216.34 | leak.example | `user13623:pass13623` |
| 2025-11-16T13:26:34.214236 | 192.168.10.252 | 93.184.216.34 | leak.example | `user20572:pass20572` |
| 2025-11-16T13:26:34.215346 | 192.168.10.242 | 93.184.216.34 | leak.example | `user11418:pass11418` |
| 2025-11-16T13:26:34.215826 | 192.168.10.57 | 93.184.216.34 | leak.example | `user18345:pass18345` |
| 2025-11-16T13:26:34.216186 | 192.168.10.191 | 93.184.216.34 | leak.example | `user24321:pass24321` |
| 2025-11-16T13:26:34.217266 | 192.168.10.136 | 93.184.216.34 | leak.example | `user8010:pass8010` |
| 2025-11-16T13:26:34.217326 | 192.168.10.178 | 93.184.216.34 | leak.example | `user17958:pass17958` |
| 2025-11-16T13:26:34.217476 | 192.168.10.191 | 93.184.216.34 | leak.example | `user11621:pass11621` |
| 2025-11-16T13:26:34.217986 | 192.168.10.42 | 93.184.216.34 | leak.example | `user23156:pass23156` |
| 2025-11-16T13:26:34.218496 | 192.168.10.177 | 93.184.216.34 | leak.example | `user13131:pass13131` |
| 2025-11-16T13:26:34.220566 | 192.168.10.166 | 93.184.216.34 | leak.example | `user9818:pass9818` |
| 2025-11-16T13:26:34.220716 | 192.168.10.93 | 93.184.216.34 | leak.example | `user12031:pass12031` |
| 2025-11-16T13:26:34.222156 | 192.168.10.162 | 93.184.216.34 | leak.example | `user17688:pass17688` |
| 2025-11-16T13:26:34.222666 | 192.168.10.68 | 93.184.216.34 | leak.example | `user21150:pass21150` |
| 2025-11-16T13:26:34.223116 | 192.168.10.130 | 93.184.216.34 | leak.example | `user22482:pass22482` |
| 2025-11-16T13:26:34.223416 | 192.168.10.24 | 93.184.216.34 | leak.example | `user1040:pass1040` |
| 2025-11-16T13:26:34.224526 | 192.168.10.211 | 93.184.216.34 | leak.example | `user19261:pass19261` |
| 2025-11-16T13:26:34.225636 | 192.168.10.153 | 93.184.216.34 | leak.example | `user24791:pass24791` |
| 2025-11-16T13:26:34.225666 | 192.168.10.253 | 93.184.216.34 | leak.example | `user14731:pass14731` |
| 2025-11-16T13:26:34.226566 | 192.168.10.66 | 93.184.216.34 | leak.example | `user18862:pass18862` |
| 2025-11-16T13:26:34.228096 | 192.168.10.161 | 93.184.216.34 | leak.example | `user5749:pass5749` |
| 2025-11-16T13:26:34.228126 | 192.168.10.105 | 93.184.216.34 | leak.example | `user9503:pass9503` |
| 2025-11-16T13:26:34.228396 | 192.168.10.204 | 93.184.216.34 | leak.example | `user8078:pass8078` |
| 2025-11-16T13:26:34.228456 | 192.168.10.195 | 93.184.216.34 | leak.example | `user13911:pass13911` |
| 2025-11-16T13:26:34.228816 | 192.168.10.191 | 93.184.216.34 | leak.example | `user4255:pass4255` |
| 2025-11-16T13:26:34.229056 | 192.168.10.159 | 93.184.216.34 | leak.example | `user9557:pass9557` |
| 2025-11-16T13:26:34.230826 | 192.168.10.240 | 93.184.216.34 | leak.example | `user10146:pass10146` |
| 2025-11-16T13:26:34.232266 | 192.168.10.247 | 93.184.216.34 | leak.example | `user12693:pass12693` |
| 2025-11-16T13:26:34.232296 | 192.168.10.245 | 93.184.216.34 | leak.example | `user20311:pass20311` |
| 2025-11-16T13:26:34.232446 | 192.168.10.181 | 93.184.216.34 | leak.example | `user4499:pass4499` |
| 2025-11-16T13:26:34.233016 | 192.168.10.21 | 93.184.216.34 | leak.example | `user23389:pass23389` |
| 2025-11-16T13:26:34.233406 | 192.168.10.92 | 93.184.216.34 | leak.example | `user23968:pass23968` |
| 2025-11-16T13:26:34.234876 | 192.168.10.219 | 93.184.216.34 | leak.example | `user6315:pass6315` |
| 2025-11-16T13:26:34.235686 | 192.168.10.57 | 93.184.216.34 | leak.example | `user21139:pass21139` |
| 2025-11-16T13:26:34.236196 | 192.168.10.251 | 93.184.216.34 | leak.example | `user18539:pass18539` |
| 2025-11-16T13:26:34.236406 | 192.168.10.82 | 93.184.216.34 | leak.example | `user21164:pass21164` |
| 2025-11-16T13:26:34.237156 | 192.168.10.110 | 93.184.216.34 | leak.example | `user19160:pass19160` |
| 2025-11-16T13:26:34.238236 | 192.168.10.155 | 93.184.216.34 | leak.example | `user12601:pass12601` |
| 2025-11-16T13:26:34.238266 | 192.168.10.193 | 93.184.216.34 | leak.example | `user193:pass193` |
| 2025-11-16T13:26:34.238986 | 192.168.10.113 | 93.184.216.34 | leak.example | `user10273:pass10273` |
| 2025-11-16T13:26:34.240546 | 192.168.10.50 | 93.184.216.34 | leak.example | `user11988:pass11988` |
| 2025-11-16T13:26:34.241776 | 192.168.10.27 | 93.184.216.34 | leak.example | `user17299:pass17299` |
| 2025-11-16T13:26:34.241896 | 192.168.10.177 | 93.184.216.34 | leak.example | `user3987:pass3987` |
| 2025-11-16T13:26:34.242196 | 192.168.10.28 | 93.184.216.34 | leak.example | `user14760:pass14760` |
| 2025-11-16T13:26:34.242856 | 192.168.10.214 | 93.184.216.34 | leak.example | `user14946:pass14946` |
| 2025-11-16T13:26:34.243786 | 192.168.10.118 | 93.184.216.34 | leak.example | `user21708:pass21708` |
| 2025-11-16T13:26:34.244116 | 192.168.10.145 | 93.184.216.34 | leak.example | `user10559:pass10559` |
| 2025-11-16T13:26:34.245646 | 192.168.10.178 | 93.184.216.34 | leak.example | `user22784:pass22784` |
| 2025-11-16T13:26:34.245706 | 192.168.10.94 | 93.184.216.34 | leak.example | `user17112:pass17112` |
| 2025-11-16T13:26:34.246246 | 192.168.10.111 | 93.184.216.34 | leak.example | `user19923:pass19923` |
| 2025-11-16T13:26:34.246366 | 192.168.10.223 | 93.184.216.34 | leak.example | `user17749:pass17749` |
| 2025-11-16T13:26:34.247206 | 192.168.10.183 | 93.184.216.34 | leak.example | `user1707:pass1707` |
| 2025-11-16T13:26:34.247596 | 192.168.10.88 | 93.184.216.34 | leak.example | `user5676:pass5676` |
| 2025-11-16T13:26:34.247716 | 192.168.10.198 | 93.184.216.34 | leak.example | `user12136:pass12136` |
| 2025-11-16T13:26:34.248016 | 192.168.10.95 | 93.184.216.34 | leak.example | `user4667:pass4667` |
| 2025-11-16T13:26:34.250836 | 192.168.10.179 | 93.184.216.34 | leak.example | `user12371:pass12371` |
| 2025-11-16T13:26:34.252156 | 192.168.10.197 | 93.184.216.34 | leak.example | `user1975:pass1975` |
| 2025-11-16T13:26:34.252216 | 192.168.10.131 | 93.184.216.34 | leak.example | `user4957:pass4957` |
| 2025-11-16T13:26:34.252516 | 192.168.10.186 | 93.184.216.34 | leak.example | `user23300:pass23300` |
| 2025-11-16T13:26:34.252636 | 192.168.10.179 | 93.184.216.34 | leak.example | `user18975:pass18975` |
| 2025-11-16T13:26:34.253806 | 192.168.10.36 | 93.184.216.34 | leak.example | `user12736:pass12736` |
| 2025-11-16T13:26:34.253986 | 192.168.10.189 | 93.184.216.34 | leak.example | `user24319:pass24319` |
| 2025-11-16T13:26:34.255816 | 192.168.10.247 | 93.184.216.34 | leak.example | `user19551:pass19551` |
| 2025-11-16T13:26:34.256386 | 192.168.10.185 | 93.184.216.34 | leak.example | `user9583:pass9583` |
| 2025-11-16T13:26:34.256896 | 192.168.10.215 | 93.184.216.34 | leak.example | `user14439:pass14439` |
| 2025-11-16T13:26:34.257016 | 192.168.10.169 | 93.184.216.34 | leak.example | `user2455:pass2455` |
| 2025-11-16T13:26:34.257376 | 192.168.10.162 | 93.184.216.34 | leak.example | `user19466:pass19466` |
| 2025-11-16T13:26:34.258096 | 192.168.10.186 | 93.184.216.34 | leak.example | `user8822:pass8822` |
| 2025-11-16T13:26:34.259476 | 192.168.10.122 | 93.184.216.34 | leak.example | `user23490:pass23490` |
| 2025-11-16T13:26:34.259626 | 192.168.10.26 | 93.184.216.34 | leak.example | `user8916:pass8916` |
| 2025-11-16T13:26:34.259656 | 192.168.10.63 | 93.184.216.34 | leak.example | `user2349:pass2349` |
| 2025-11-16T13:26:34.259956 | 192.168.10.228 | 93.184.216.34 | leak.example | `user5054:pass5054` |
| 2025-11-16T13:26:34.260676 | 192.168.10.210 | 93.184.216.34 | leak.example | `user210:pass210` |
| 2025-11-16T13:26:34.261426 | 192.168.10.170 | 93.184.216.34 | leak.example | `user15664:pass15664` |
| 2025-11-16T13:26:34.262266 | 192.168.10.143 | 93.184.216.34 | leak.example | `user24781:pass24781` |
| 2025-11-16T13:26:34.263016 | 192.168.10.126 | 93.184.216.34 | leak.example | `user12318:pass12318` |
| 2025-11-16T13:26:34.263106 | 192.168.10.198 | 93.184.216.34 | leak.example | `user9850:pass9850` |
| 2025-11-16T13:26:34.264846 | 192.168.10.22 | 93.184.216.34 | leak.example | `user20596:pass20596` |
| 2025-11-16T13:26:34.266436 | 192.168.10.242 | 93.184.216.34 | leak.example | `user5322:pass5322` |
| 2025-11-16T13:26:34.267216 | 192.168.10.101 | 93.184.216.34 | leak.example | `user21183:pass21183` |
| 2025-11-16T13:26:34.267756 | 192.168.10.71 | 93.184.216.34 | leak.example | `user16835:pass16835` |
| 2025-11-16T13:26:34.268626 | 192.168.10.199 | 93.184.216.34 | leak.example | `user6041:pass6041` |
| 2025-11-16T13:26:34.269436 | 192.168.10.202 | 93.184.216.34 | leak.example | `user12902:pass12902` |
| 2025-11-16T13:26:34.270096 | 192.168.10.135 | 93.184.216.34 | leak.example | `user9025:pass9025` |
| 2025-11-16T13:26:34.270366 | 192.168.10.109 | 93.184.216.34 | leak.example | `user3665:pass3665` |
| 2025-11-16T13:26:34.270516 | 192.168.10.135 | 93.184.216.34 | leak.example | `user1913:pass1913` |
| 2025-11-16T13:26:34.270606 | 192.168.10.167 | 93.184.216.34 | leak.example | `user14899:pass14899` |
| 2025-11-16T13:26:34.270846 | 192.168.10.162 | 93.184.216.34 | leak.example | `user24546:pass24546` |
| 2025-11-16T13:26:34.271146 | 192.168.10.232 | 93.184.216.34 | leak.example | `user15472:pass15472` |
| 2025-11-16T13:26:34.271296 | 192.168.10.78 | 93.184.216.34 | leak.example | `user2364:pass2364` |
| 2025-11-16T13:26:34.273066 | 192.168.10.83 | 93.184.216.34 | leak.example | `user15831:pass15831` |
| 2025-11-16T13:26:34.273336 | 192.168.10.214 | 93.184.216.34 | leak.example | `user976:pass976` |
| 2025-11-16T13:26:34.275376 | 192.168.10.74 | 93.184.216.34 | leak.example | `user22680:pass22680` |
| 2025-11-16T13:26:34.275676 | 192.168.10.60 | 93.184.216.34 | leak.example | `user9204:pass9204` |
| 2025-11-16T13:26:34.277266 | 192.168.10.233 | 93.184.216.34 | leak.example | `user9631:pass9631` |
| 2025-11-16T13:26:34.278586 | 192.168.10.49 | 93.184.216.34 | leak.example | `user16051:pass16051` |
| 2025-11-16T13:26:34.279006 | 192.168.10.3 | 93.184.216.34 | leak.example | `user14989:pass14989` |
| 2025-11-16T13:26:34.279516 | 192.168.10.26 | 93.184.216.34 | leak.example | `user18314:pass18314` |
| 2025-11-16T13:26:34.279576 | 192.168.10.186 | 93.184.216.34 | leak.example | `user9584:pass9584` |
| 2025-11-16T13:26:34.280086 | 192.168.10.150 | 93.184.216.34 | leak.example | `user19962:pass19962` |
| 2025-11-16T13:26:34.280266 | 192.168.10.1 | 93.184.216.34 | leak.example | `user22353:pass22353` |
| 2025-11-16T13:26:34.282366 | 192.168.10.14 | 93.184.216.34 | leak.example | `user11190:pass11190` |
| 2025-11-16T13:26:34.283026 | 192.168.10.12 | 93.184.216.34 | leak.example | `user17538:pass17538` |
| 2025-11-16T13:26:34.283896 | 192.168.10.215 | 93.184.216.34 | leak.example | `user5295:pass5295` |
| 2025-11-16T13:26:34.284106 | 192.168.10.134 | 93.184.216.34 | leak.example | `user11310:pass11310` |
| 2025-11-16T13:26:34.284736 | 192.168.10.142 | 93.184.216.34 | leak.example | `user20208:pass20208` |
| 2025-11-16T13:26:34.285786 | 192.168.10.161 | 93.184.216.34 | leak.example | `user14385:pass14385` |
| 2025-11-16T13:26:34.288276 | 192.168.10.27 | 93.184.216.34 | leak.example | `user11203:pass11203` |
| 2025-11-16T13:26:34.290346 | 192.168.10.195 | 93.184.216.34 | leak.example | `user17975:pass17975` |
| 2025-11-16T13:26:34.291636 | 192.168.10.25 | 93.184.216.34 | leak.example | `user6375:pass6375` |
| 2025-11-16T13:26:34.291666 | 192.168.10.23 | 93.184.216.34 | leak.example | `user15517:pass15517` |
| 2025-11-16T13:26:34.291756 | 192.168.10.216 | 93.184.216.34 | leak.example | `user12916:pass12916` |
| 2025-11-16T13:26:34.292356 | 192.168.10.160 | 93.184.216.34 | leak.example | `user20988:pass20988` |
| 2025-11-16T13:26:34.292866 | 192.168.10.92 | 93.184.216.34 | leak.example | `user3648:pass3648` |
| 2025-11-16T13:26:34.292926 | 192.168.10.142 | 93.184.216.34 | leak.example | `user3190:pass3190` |
| 2025-11-16T13:26:34.293226 | 192.168.10.140 | 93.184.216.34 | leak.example | `user13094:pass13094` |
| 2025-11-16T13:26:34.293436 | 192.168.10.22 | 93.184.216.34 | leak.example | `user24152:pass24152` |
| 2025-11-16T13:26:34.293496 | 192.168.10.222 | 93.184.216.34 | leak.example | `user984:pass984` |
| 2025-11-16T13:26:34.293556 | 192.168.10.12 | 93.184.216.34 | leak.example | `user22110:pass22110` |
| 2025-11-16T13:26:34.294336 | 192.168.10.173 | 93.184.216.34 | leak.example | `user8047:pass8047` |
| 2025-11-16T13:26:34.294396 | 192.168.10.88 | 93.184.216.34 | leak.example | `user7962:pass7962` |
| 2025-11-16T13:26:34.294426 | 192.168.10.232 | 93.184.216.34 | leak.example | `user19790:pass19790` |
| 2025-11-16T13:26:34.294696 | 192.168.10.109 | 93.184.216.34 | leak.example | `user7729:pass7729` |
| 2025-11-16T13:26:34.294786 | 192.168.10.101 | 93.184.216.34 | leak.example | `user1625:pass1625` |
| 2025-11-16T13:26:34.295356 | 192.168.10.95 | 93.184.216.34 | leak.example | `user3397:pass3397` |
| 2025-11-16T13:26:34.295806 | 192.168.10.85 | 93.184.216.34 | leak.example | `user19389:pass19389` |
| 2025-11-16T13:26:34.296046 | 192.168.10.78 | 93.184.216.34 | leak.example | `user19382:pass19382` |
| 2025-11-16T13:26:34.296076 | 192.168.10.205 | 93.184.216.34 | leak.example | `user24081:pass24081` |
| 2025-11-16T13:26:34.297006 | 192.168.10.37 | 93.184.216.34 | leak.example | `user3593:pass3593` |
| 2025-11-16T13:26:34.297336 | 192.168.10.56 | 93.184.216.34 | leak.example | `user20122:pass20122` |
| 2025-11-16T13:26:34.297456 | 192.168.10.93 | 93.184.216.34 | leak.example | `user21683:pass21683` |
| 2025-11-16T13:26:34.298536 | 192.168.10.250 | 93.184.216.34 | leak.example | `user20824:pass20824` |
| 2025-11-16T13:26:34.299226 | 192.168.10.65 | 93.184.216.34 | leak.example | `user23941:pass23941` |
| 2025-11-16T13:26:34.300996 | 192.168.10.129 | 93.184.216.34 | leak.example | `user11051:pass11051` |
| 2025-11-16T13:26:34.301266 | 192.168.10.225 | 93.184.216.34 | leak.example | `user6575:pass6575` |
| 2025-11-16T13:26:34.301896 | 192.168.10.194 | 93.184.216.34 | leak.example | `user13402:pass13402` |
| 2025-11-16T13:26:34.302706 | 192.168.10.242 | 93.184.216.34 | leak.example | `user496:pass496` |
| 2025-11-16T13:26:34.302736 | 192.168.10.144 | 93.184.216.34 | leak.example | `user13098:pass13098` |
| 2025-11-16T13:26:34.302886 | 192.168.10.213 | 93.184.216.34 | leak.example | `user6309:pass6309` |
| 2025-11-16T13:26:34.303576 | 192.168.10.29 | 93.184.216.34 | leak.example | `user18063:pass18063` |
| 2025-11-16T13:26:34.303606 | 192.168.10.138 | 93.184.216.34 | leak.example | `user8774:pass8774` |
| 2025-11-16T13:26:34.304056 | 192.168.10.170 | 93.184.216.34 | leak.example | `user6520:pass6520` |
| 2025-11-16T13:26:34.304206 | 192.168.10.140 | 93.184.216.34 | leak.example | `user13602:pass13602` |
| 2025-11-16T13:26:34.304386 | 192.168.10.162 | 93.184.216.34 | leak.example | `user13624:pass13624` |
| 2025-11-16T13:26:34.304596 | 192.168.10.0 | 93.184.216.34 | leak.example | `user1270:pass1270` |
| 2025-11-16T13:26:34.305916 | 192.168.10.148 | 93.184.216.34 | leak.example | `user23262:pass23262` |
| 2025-11-16T13:26:34.305946 | 192.168.10.18 | 93.184.216.34 | leak.example | `user1542:pass1542` |
| 2025-11-16T13:26:34.306516 | 192.168.10.103 | 93.184.216.34 | leak.example | `user8231:pass8231` |
| 2025-11-16T13:26:34.306636 | 192.168.10.122 | 93.184.216.34 | leak.example | `user9520:pass9520` |
| 2025-11-16T13:26:34.306726 | 192.168.10.159 | 93.184.216.34 | leak.example | `user20225:pass20225` |
| 2025-11-16T13:26:34.306756 | 192.168.10.237 | 93.184.216.34 | leak.example | `user23351:pass23351` |
| 2025-11-16T13:26:34.306876 | 192.168.10.211 | 93.184.216.34 | leak.example | `user22055:pass22055` |
| 2025-11-16T13:26:34.307806 | 192.168.10.91 | 93.184.216.34 | leak.example | `user7711:pass7711` |
| 2025-11-16T13:26:34.308106 | 192.168.10.229 | 93.184.216.34 | leak.example | `user21311:pass21311` |
| 2025-11-16T13:26:34.308496 | 192.168.10.2 | 93.184.216.34 | leak.example | `user18036:pass18036` |
| 2025-11-16T13:26:34.309756 | 192.168.10.232 | 93.184.216.34 | leak.example | `user7090:pass7090` |
| 2025-11-16T13:26:34.310626 | 192.168.10.221 | 93.184.216.34 | leak.example | `user14699:pass14699` |
| 2025-11-16T13:26:34.310866 | 192.168.10.68 | 93.184.216.34 | leak.example | `user22928:pass22928` |
| 2025-11-16T13:26:34.312906 | 192.168.10.221 | 93.184.216.34 | leak.example | `user15461:pass15461` |
| 2025-11-16T13:26:34.313056 | 192.168.10.174 | 93.184.216.34 | leak.example | `user19224:pass19224` |
| 2025-11-16T13:26:34.313446 | 192.168.10.199 | 93.184.216.34 | leak.example | `user21535:pass21535` |
| 2025-11-16T13:26:34.313776 | 192.168.10.122 | 93.184.216.34 | leak.example | `user10028:pass10028` |
| 2025-11-16T13:26:34.314376 | 192.168.10.199 | 93.184.216.34 | leak.example | `user8327:pass8327` |
| 2025-11-16T13:26:34.315216 | 192.168.10.50 | 93.184.216.34 | leak.example | `user14528:pass14528` |
| 2025-11-16T13:26:34.315636 | 192.168.10.205 | 93.184.216.34 | leak.example | `user20017:pass20017` |
| 2025-11-16T13:26:34.316056 | 192.168.10.202 | 93.184.216.34 | leak.example | `user18744:pass18744` |
| 2025-11-16T13:26:34.317316 | 192.168.10.233 | 93.184.216.34 | leak.example | `user995:pass995` |
| 2025-11-16T13:26:34.317586 | 192.168.10.145 | 93.184.216.34 | leak.example | `user15385:pass15385` |
| 2025-11-16T13:26:34.318366 | 192.168.10.169 | 93.184.216.34 | leak.example | `user11599:pass11599` |
| 2025-11-16T13:26:34.318636 | 192.168.10.11 | 93.184.216.34 | leak.example | `user7123:pass7123` |
| 2025-11-16T13:26:34.318876 | 192.168.10.222 | 93.184.216.34 | leak.example | `user18256:pass18256` |
| 2025-11-16T13:26:34.319686 | 192.168.10.123 | 93.184.216.34 | leak.example | `user2917:pass2917` |
| 2025-11-16T13:26:34.320436 | 192.168.10.129 | 93.184.216.34 | leak.example | `user3939:pass3939` |
| 2025-11-16T13:26:34.321756 | 192.168.10.9 | 93.184.216.34 | leak.example | `user10931:pass10931` |
| 2025-11-16T13:26:34.322806 | 192.168.10.131 | 93.184.216.34 | leak.example | `user10037:pass10037` |
| 2025-11-16T13:26:34.323226 | 192.168.10.140 | 93.184.216.34 | leak.example | `user8522:pass8522` |
| 2025-11-16T13:26:34.323376 | 192.168.10.0 | 93.184.216.34 | leak.example | `user2032:pass2032` |
| 2025-11-16T13:26:34.323736 | 192.168.10.95 | 93.184.216.34 | leak.example | `user14319:pass14319` |
| 2025-11-16T13:26:34.324516 | 192.168.10.211 | 93.184.216.34 | leak.example | `user9101:pass9101` |
| 2025-11-16T13:26:34.324546 | 192.168.10.100 | 93.184.216.34 | leak.example | `user12800:pass12800` |
| 2025-11-16T13:26:34.326136 | 192.168.10.13 | 93.184.216.34 | leak.example | `user6617:pass6617` |
| 2025-11-16T13:26:34.327276 | 192.168.10.194 | 93.184.216.34 | leak.example | `user12386:pass12386` |
| 2025-11-16T13:26:34.328836 | 192.168.10.104 | 93.184.216.34 | leak.example | `user5946:pass5946` |

- (Only first 200 of 25000 shown.)

### Suspicious DNS queries (C2 indicators)

- Number of suspicious DNS queries matched: **100000**

Top matched suspicious domains:

- mjswcy3pnyzt.darkc2.io (3794)
- mjswcy3pny2t.darkc2.io (3792)
- mjswcy3pnyyt.darkc2.io (3792)
- mjswcy3pnyzd.evilserver.org (3761)
- mjswcy3pny2d.darkc2.io (3759)
- mjswcy3pny4t.evilserver.org (3745)
- mjswcy3pny3t.darkc2.io (3739)
- mjswcy3pny4t.darkc2.io (3734)
- mjswcy3pny3d.darkc2.io (3733)
- mjswcy3pny2t.c2bad.net (3733)
- mjswcy3pny3d.c2bad.net (3729)
- mjswcy3pnyyt.evilserver.org (3725)
- mjswcy3pnyzd.darkc2.io (3724)
- mjswcy3pny4d.evilserver.org (3716)
- mjswcy3pnyzt.evilserver.org (3697)
- mjswcy3pny4d.c2bad.net (3697)
- mjswcy3pny3t.c2bad.net (3697)
- mjswcy3pny2d.evilserver.org (3697)
- mjswcy3pny4d.darkc2.io (3697)
- mjswcy3pny3t.evilserver.org (3674)

### Suspicious HTTP callback hosts

- Number of HTTP requests to C2-like hosts: **72404**
- c2.example: 72404

## Conclusion & Recommendations
- Use end-to-end TLS for all authentication; avoid sending credentials in plaintext.
- Block or monitor DNS queries to suspicious domains (create IDS/suricata rules for matched patterns).
- Investigate the top source IPs identified in the Top Talkers chart; correlate with endpoint logs.
- If C2 activity is suspected, isolate affected hosts and perform host-based forensics (memory, disk imaging).

## Appendix: TShark extraction commands
```
tshark -r case_study_large.pcap -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.uri > http_requests.tsv
tshark -r case_study_large.pcap -Y "http.authorization" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.authorization > auth_headers.tsv
tshark -r case_study_large.pcap -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name > dns_queries.tsv
tshark -r case_study_large.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len > timeline.tsv
```
