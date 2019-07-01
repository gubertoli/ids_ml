## To reduce original pcap file
tcpdump -r probe_known_attacks.pcap -w new_files -C 800

## Wireshark filters to identify nmap scan 
### TCP SYN Scan
tcp && tcp.flags.fin ==1 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

### XMAS Scan
tcp && tcp.flags==0x29 && tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1

### NULL Scan
tcp && tcp.flags==0x00 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

### FIN Scan
tcp.flags==0x01 && tcp.flags.fin==1 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)

Probable Attacker: 192.198.0.200

http://blog.extremehacking.org/blog/2015/07/22/packet-fingerprinting-with-wireshark-and-detecting-nmap-scans/
