---
title: Converting DoH to DNS
date: 2021-01-06
categories: [research, networking]
tags: [research, school, dns, doh, networking]     # TAG names should always be lowercase
---
In a [previous post]({% post_url 2019-12-31-Investigating-DoH %}) I wrote about investigations
that I performed on DNS over HTTPS (DoH). That research was performed as part of
[Cyber Security Research](https://catalog.dsu.edu/preview_course_nopop.php?catoid=32&coid=20604). During
[Security Tool Development](https://catalog.dsu.edu/preview_course_nopop.php?catoid=32&coid=20607), I
expanded on that research by implementing a Python script which creates DNS wire
format packets from a DoH packet capture. This post describes how that script
was made and how it works.

# Updates to gen_doh.py
In addition to the use of `sslkeylog` which was discussed in the previous post, I needed to update the `client_protocol.py` file. Line 45 of that file contains:
```python
sslctx = utils.create_custom_ssl_context(
            insecure=self.args.insecure,
            cafile=self.args.cafile
        )
```
Due to the use of self-signed certificates, `insecure` needs to be set to True. I could not find a code path which allowed me to do that, and therefore had to modify line 46 to explicitly do so.
```python
sslctx = utils.create_custom_ssl_context(
            insecure=True,
            cafile=self.args.cafile
        )
```
Once these changes are made, `gen_doh.py` can be used to generate the test data.
# doh2dns.py
Rommel once said "no plan survives contact with the enemy" and that is true in cyber security as well.

## Initial design goals
My initial plan for extracting the information from the captured packets was to use the `tshark` command line utility to read the packets and use its `ssl.keylog_file` to decrypt those packets as I had previously done during CTF competitions. Once the capture file was read and decrypted, I would save the decrypted contents to a new .pcap. I could then process those packets, looking for DoH queries. However, I discovered that `tshark` decrypts packets for display, but does not actually buffer a decrypted packet which can be written to disk.

Once that was discovered, my new plan was to call tshark from a Python script and then parse the output of the command, using a regular expression to search for "GET.\*dns=(.\*)\b". This approach proved promising, as I was able to detect the queries. Further text processing was needed to extract the specific information that I wanted. This approach can be found in a [previous commit](https://github.com/kimobu/doh-investigation/blob/a853cbc5c0f57bc8b56bc313b0b020afce27f4c8/doh2dns.py).

## Final design
Thankfully, this class was collaborative in nature and a [fellow student](https://github.com/daddycocoaman) suggested that I look into the [pyshark](https://github.com/KimiNewt/pyshark/) package. Pyshark is a Python wrapper for tshark and allows for decrypted packets to be buffered in memory. With Pyshark, I could perform the programatic packet interactions that I wanted. With this package, the new workflow became:
1. Read a Pcap
2. Correlate packet streams
3. Find DoH answers
4. Recreate DNS packets with Scapy
5. Retransmit DNS packets

### Reading the Pcap and Correlating Streams
```python
def get_streams():
    print("[+] Retrieving streams")
    cap = pyshark.FileCapture(args.pcap,
                              override_prefs={
                                  'tls.keylog_file': args.sslkeylogfile
                              })
    cap.load_packets()
    streams = {}

    for packet in tqdm(cap, bar_format="{l_bar}{bar}"):
        if packet.__contains__('http2'):
            if packet.http2.streamid in streams:
                streams[packet.http2.streamid].append(packet)
            else:
                streams[packet.http2.streamid] = []
                streams[packet.http2.streamid].append(packet)
    print(f"[+] Identified {len(streams)} different streams")
    return streams
```
In this first code block, the script reads the Pcap and correlates the streams. The Pcap is ready by using pyshark's FileCapture() method. The first argument is the Pcap file to read. I also supply a second argument, `override_prefs`, which sets additional options to control how the method functions by passing a dictionary of options. In this case, 'tls.keylog_file' is used to specify the keylog file to decrypt the packets. Once the FileCapture object is created, its `load_packets()` method is used to read the packets from disk.

Next, `tqdm()` is used to display a progress bar for the processing of packets. The script iterates each packet and uses the `__contains__()` method to look for the HTTP2 protocol, which is the protocol used by DoH. If the packet uses the HTTP2 protocol, the packet is appended to a list of packets sharing the same streamid.
### Finding DoH answers
```python
def process_streams(streams):
    print("[ ] Finding DNS answers...")
    dns_answers = []
    for streamid, packets in tqdm(streams.items(), bar_format="{l_bar}{bar}"):
        for packet in tqdm(packets, bar_format="{l_bar}{bar}"):
            if packet.__contains__('http2'):
                if packet.http2.get_field('dns_a')\
                        or packet.http2.get_field('dns_aaaa')\
                        or packet.http2.get_field('dns.count.answers') == '0':
                    # An answer was found.
                    # We can reconstruct a DNS packet using this information.
                    packetdata = {}
                    # Client and Server fields are reversed
                    packetdata['client'] = packet.ip.dst
                    packetdata['server'] = packet.ip.src
                    packetdata['query'] =\
                        packet.http2.get_field('dns_qry_name')
                    if packet.http2.get_field('dns_a'):
                        packetdata['answer'] =\
                            packet.http2.get_field('dns_a') or "NXDOMAIN"
                        packetdata['type'] = 'A'
                    else:
                        packetdata['answer'] =\
                            packet.http2.get_field('dns_aaaa') or "NXDOMAIN"
                        packetdata['type'] = 'AAAA'
                    dns_answers.append(packetdata)
    print(f"[+] Found {len(dns_answers)} DNS answers")
    return dns_answers
```
The next step is to find DoH answers. The script accomplishes this by iterating each stream and then each packet. In each HTTP2 packet, it looks for one of the following fields: 'dns_a' for A records, 'dns_aaaa' for AAAA records, and 'dns.count.answers' for NX records.

If an answer is found, the script extracts useful information from the packet and creates a new object with that data. The 'client' is the computer which initiated the DNS query and is retrieved from the packet's destination IP address (since this packet is an answer, the destination is the client). The 'server' is the packet's source IP address. The 'query' is retrieved from the HTTP2 field 'dns_qry_name' and indicates the hostname that was queried, e.g. www.example.com. The 'type' is set appropriately based on IPv4 or IPv6 answers from the packet. Finally, the 'answer' is either the answer from the DoH server or NXDOMAIN is 'dns.count.answers' was set to 0.
### Recreate DNS Packets with Scapy and Retransmit the Query
[Scapy](https://scapy.net) is a Python package which allows you to craft custom packets in Python. There are several uses for Scapy in the cyber security space. For example, in another class I built a Python script with Scapy to act as a [Network Address Translation](https://github.com/kimobu/python-nat) device by sniffing packets on one interface, modifying the packets, and then transmitting them out another interface. That work served as inspiration for this project.
```python
def craft_query(packetdata):
    dns_query = IP(dst=packetdata['server'],
                   src=packetdata['client'])\
                /UDP(sport=RandShort(),
                     dport=53)\
                /DNS(rd=1,
                     qd=DNSQR(qname=packetdata['query'],
                              qtype=packetdata['type']))
    return dns_query


def replay_packet(packet):
    send(packet.getlayer(IP), iface=args.replay_interface, verbose=0)
```
In `craft_query()` we pass the packet data extracted from the previous step and create a new DNS packet. The syntax to do this in Scapy is to call the IP() constructor and pass in the source and destination addresses. Then, call the UDP() constructor. The source port can be set to RandShort(), which will pick a random number from 0-65535. Using RandShort() was efficient but not necessarily effective - a better solution would have been to choose a number in the host operating system's ephemeral port range. The destination port is set to 53, as that is what DNS typically uses. Lastly, call the DNS() constructor, setting recursive desired to 1 and the query and type as appropriate.

With a new packet in memory, the last action is to transmit the packet. Scapy's `send()` function is used. The first option is the packet, starting at the IP layer and allowing the operating system to handle layers below that. The second option defines the interface on which to transmit. The last option is verbosity. In this script, I do not display information about transmitted packets.
# Conclusion
At this point, packets would be transmitted out of another interface. My thought here is that the specified interface would feed onto a LAN monitored by a Network Monitoring System where any number of algorithms could be used to detect malicious activity. Future work in this project could include decrypting TLS 1.3 as well as real-time decryption of packets.
