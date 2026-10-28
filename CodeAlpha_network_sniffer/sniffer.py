#!/usr/bin/env python3
"""
Basic Network Sniffer (using Scapy)

Captures packets, shows source/destination IPs, protocol, ports,
and a payload preview. Prints a summary at the end and can save
the capture to a .pcap file (openable in Wireshark).

Run as Administrator (Windows) or with sudo (Linux/macOS).
Only capture traffic on networks you own or have permission to monitor.
"""

import argparse
import datetime
from collections import Counter

from scapy.all import (
    sniff, wrpcap, get_if_list,
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
)

# Well-known ports -> application protocol names
PORT_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
}

# IP protocol numbers -> names (for packets that are not TCP/UDP/ICMP)
IP_PROTOS = {
    2: "IGMP", 41: "IPv6-encap", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF",
}

stats = Counter()      # counts packets per protocol
captured = []          # keeps packets so we can save them as .pcap
options = None         # filled in main()


def payload_preview(pkt, limit):
    """Return a printable preview of the packet payload (or None)."""
    if Raw not in pkt:
        return None
    data = bytes(pkt[Raw].load)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def service_name(sport, dport):
    """Guess the application protocol from the port numbers."""
    return PORT_NAMES.get(dport) or PORT_NAMES.get(sport)


def handle_packet(pkt):
    """Called by Scapy for every captured packet."""
    captured.append(pkt)
    now = datetime.datetime.now().strftime("%H:%M:%S")
    size = len(pkt)

    src = dst = proto = "?"
    details = ""

    # ---- Layer 2: ARP (no IP layer) ----
    if ARP in pkt:
        arp = pkt[ARP]
        proto = "ARP"
        src, dst = arp.psrc, arp.pdst
        details = "who-has request" if arp.op == 1 else "is-at reply"

    # ---- Layer 3: IPv4 / IPv6 ----
    elif IP in pkt or IPv6 in pkt:
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        src, dst = ip.src, ip.dst
        ttl = ip.ttl if IP in pkt else ip.hlim
        details = f"ttl={ttl}"

        # ---- Layer 4: TCP / UDP / ICMP ----
        if TCP in pkt:
            tcp = pkt[TCP]
            proto = "TCP"
            app = service_name(tcp.sport, tcp.dport)
            if app:
                proto += f"/{app}"
            details += f" {tcp.sport}->{tcp.dport} flags={tcp.flags}"
        elif UDP in pkt:
            udp = pkt[UDP]
            proto = "UDP"
            app = service_name(udp.sport, udp.dport)
            if app:
                proto += f"/{app}"
            details += f" {udp.sport}->{udp.dport}"
            if DNS in pkt and DNSQR in pkt and pkt[DNS].qr == 0:
                details += f" query={pkt[DNSQR].qname.decode(errors='ignore')}"
        elif ICMP in pkt:
            proto = "ICMP"
            details += f" type={pkt[ICMP].type}"
        else:
            number = ip.proto if IP in pkt else ip.nh
            proto = IP_PROTOS.get(number, f"IP-proto-{number}")
    else:
        proto = "OTHER"
        if Ether in pkt:
            details = f"ethertype={hex(pkt[Ether].type)}"

    stats[proto.split("/")[0]] += 1

    line = f"[{now}] {proto:<11} {src} -> {dst}  len={size}  {details}"
    print(line)

    if options.payload:
        preview = payload_preview(pkt, options.payload_len)
        if preview:
            print(f"    payload: {preview}")


def print_summary():
    total = sum(stats.values())
    print("\n" + "=" * 45)
    print(f"Capture finished. Total packets: {total}")
    for proto, count in stats.most_common():
        print(f"  {proto:<8} {count}")
    print("=" * 45)


def main():
    global options
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument("-i", "--iface", help="network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="stop after N packets (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp", "udp port 53", "host 8.8.8.8"')
    parser.add_argument("-p", "--payload", action="store_true",
                        help="show a preview of packet payloads")
    parser.add_argument("--payload-len", type=int, default=60,
                        help="bytes of payload to preview (default 60)")
    parser.add_argument("-w", "--save", help="save capture to this .pcap file")
    parser.add_argument("--list", action="store_true",
                        help="list network interfaces and exit")
    options = parser.parse_args()

    if options.list:
        for name in get_if_list():
            print(name)
        return

    print("Sniffing started... press Ctrl+C to stop.\n")
    try:
        sniff(iface=options.iface, filter=options.filter or None,
              prn=handle_packet, count=options.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied: run as Administrator / with sudo.")
        return

    print_summary()

    if options.save and captured:
        wrpcap(options.save, captured)
        print(f"Saved {len(captured)} packets to {options.save}")


if __name__ == "__main__":
    main()