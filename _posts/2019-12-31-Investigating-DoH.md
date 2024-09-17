---
title: Investigating DoH
date: 2019-12-31
categories: [research, networking]
tags: [networking, research, school, doh, dns]
---
# DNS Security
As a plain-text protocol, DNS lacks Confidentiality, Integrity, and Availability (CIA) protections. An attacker who can observe DNS activity can see where the DNS request originated from, where responses came from, what the query and response were, or tamper with the response.

DNS over HTTPS (DoH) effectively mitigates many of those weaknesses. Instead of being a plain-text protocol over UDP, DoH is an exchange of DNS queries and responses over a TLS encrypted connection, using the HTTP2 protocol to transmit messages. Because of this encryption, an attacker can neither observe nor tamper with DoH queries and responses.

DNS is used by malware to perform lookups on Command and Control (C2) servers. Malware can also use DNS as a covert-channel, embedding commands or exfiltrated data as encoded values within a DNS datagram. Security software (i.e. Intrusion Detection Systems \[IDS\]) observes network traffic to identify known C2 domains being resolved (signature matching). An IDS can also use anomaly detection to identify potential malicious use of DNS through various features of the DNS query or response.

# Detecting Malicious DNS
In the following table, some of the features which are used in IDS detecction algorithms are presented.

| Feature | Description | Visible in DoH |
|---------|-------------|----------------|
|Domain name|The name that was queried|No|
|IP address|Either the source or destination IP address of the DNS query |Yes|
|Port|Either the source or destination port of the DNS query|Yes|
|Timestamp|When the DNS query or response took place|Maybe - Need to be able to differentiate between DoH and other HTTPS traffic|
|Record type|The type of DNS record queried - A, AAAA, MX, etc|No|
|NXDOMAIN|A DNS response of "no domain record" - useful in identifying malware using a Domain Generating Algorithm (DGA)|No|
|Web presence|An active lookup performed by the IDS, checking for whether there is a "legitimate" web presence of the queried domain|No, requires knowledge of the resolved domain name|
|Entropy|The entropy of the queried domain - useful in identifying DNS being used as a covert channel|No|
|Unique query ratio|The number of unique queries from a given DNS client|No|
|Query volume|The total number of DNS queries from a given client|No|
|Longest meaningful word|The longest "real" word that is part of the resolved domain. "Real" domains/services should use real words somewhere in the domain or subdomain|No|
|Unique subdomains|The number of unique subdomains - used in covert channel detection. |No|
|Number of subdomains|The total number of subdomains queried in a given domain|No|

As we can see from that table, most of the features of a DNS query/response which are used to detect malware using DNS are not available due to the TLS encryption. Further, if the HTTP GET method is used, the format of the query is different than what is used in normal DNS, so additional processing of packets must occur to obtain the features in a format that can be processed by exiting systems.

# Generating DoH Test Data
To generate DoH test data, I used a CentOS 8 VM with 4x 3.2Ghz CPU and 8GB RAM.

Facebook provides a [DoH Proxy Server and a client](https://facebookexperimental.github.io/doh-proxy/) which were used to generate the traffic. The software is available as a PIP package.

`pip3 install doh-proxy sslkeylog`
A TLS certificate and key are needed.
`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout selfsigned.key -out selfsigned.pem`
Now the DoH proxy can be ran.
`doh-proxy --upstream your_upstream_dns --certfile=./selfsigned.pem --keyfile=./selfsigned.key --listen-address=0.0.0.0`

At this point, you should be able to point a client which can use DoH to the DoH Proxy and resolve domain names. I had trouble getting Firefox on a Windows 10 VM to consistently use the DoH Proxy, so I ended up using the `doh-client` instead. This had the added benefit of easily scripting queries. I used the first 100,000 records of the [Majestic Million](https://majestic.com/reports/majestic-million) dataset. The full script used to generate queries is availble [on Github](https://raw.githubusercontent.com/kimobu/doh-investigation/master/gen_doh.py).

One last thing I needed to do was modify the `utils.py` file of the DoH Proxy and add the following lines. The SSLKeyLog package will save TLS keys exchanged during TLS session setup. This is a requirement in order to decrypt TLS 1.3, which uses Forward Secrecy.
```
import sslkeylog
sslkeylog.set_keylog("/root/sslkeylog.txt")
```
While executing the `gen_doh.py` script, I used `tcpdump` to capture the traffic.
`tcpdump -i lo -s 65535 -w doh_get.pcap`
Once the script has finished, the PCAP can be opened with Wireshark and confirm that all of the traffic is TLS encrypted. Using `tshark` and the SSLKeyLog file, we can decrypt the traffic to see what DoH looks like on the wire.
`time tshark -r doh_get.pcap -V -x  -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:127.0.0.1,443,http,selfsigned.pem" -o "ssl.keylog_file:sslkeylog.txt" -w doh_get_decrypted.pcap`
This process was performed once for GET traffic and once for POST. The average time to decrypt those two PCAPs was 876.5 seconds.

|HTTP Action|Packets|File size|Decrypted file size|
|-----------|-------|---------|-------------------|
|GET        |2,078,688|504,824,100|542,107,992|
|POST       |2,177,897|516,151,600|555,337,372|

The encrypted DoH traffic provides only Netflow information.
(note: image lost to the ether)

Once unencrypted, we can see the queried domain and response. When using GET, the domain query is base64 encoded, contributing to additional processing needed to transform the data into a usable format.
(note: image lost to the ether)
# Future work
* Analysis of TLS decryption on larger datasets, discriminating between DoH and non-DoH traffic
* Transformation of DoH traffic to DNS wire format for feeding into IDS
