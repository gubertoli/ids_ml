## To reduce original pcap file
```
tcpdump -r probe_known_attacks.pcap -w new_files -C 800
```
```
editcap -c 3000000 probe_known_attacks.pcap new_files.pcap
```
## Extracting headers (pcap -> tsv)
```
tshark -r probe_known_attacks.pcap -T fields -e ip.src -e ip.dst -e ip.opt.type -e ip.len -e ip.id 
  -e ip.frag_offset -e ip.flags.rb -e ip.flags.df -e ip.flags.mf -e ip.proto 
  -e ip.checksum -e udp.srcport -e udp.dstport -e udp.length -e udp.checksum 
  -e icmp.type -e icmp.code -e icmp.checksum -e tcp.len -e tcp.srcport 
  -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.flags.fin -e tcp.flags.syn 
  -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack -e tcp.flags.urg 
  -e eth.len -E separator=/t -E header=y > pcap_to_csv.tsv
```

## Wireshark filters to identify nmap scan 
### TCP SYN Scan
tcp && tcp.flags.fin ==1 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

### XMAS Scan
tcp && tcp.flags==0x29 && tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1

### NULL Scan
tcp && tcp.flags==0x00 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

### FIN Scan
tcp.flags==0x01 && tcp.flags.fin==1 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

http://blog.extremehacking.org/blog/2015/07/22/packet-fingerprinting-with-wireshark-and-detecting-nmap-scans/
