Basic Network Sniffer - Python (Scapy)
Name: <Rehan Ahmad>  

Requirements:
  Python 3.8+, Scapy (pip install scapy)
  Windows: Npcap installed (WinPcap compatible mode)

How to run (as Administrator):
  python sniffer.py                       -> capture until Ctrl+C
  python sniffer.py -c 30                 -> capture 30 packets
  python sniffer.py -f "udp port 53"      -> filter DNS traffic
  python sniffer.py -p                    -> show payloads
  python sniffer.py -c 50 -w capture.pcap -> save capture