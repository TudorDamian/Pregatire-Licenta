import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime


# Returnează lista de pachete parse într-un format JSON-friendly.
def parse_pcap(file_path: str):
    packets = scapy.rdpcap(file_path)
    parsed_packets = []
    connection_isn = {}
    start_time = None

    for idx, pkt in enumerate(packets):
        try:
            if start_time is None:
                start_time = pkt.time
            rel_time = round(pkt.time - start_time, 6)

            src = pkt[IP].src if pkt.haslayer(IP) else (pkt[scapy.IPv6].src if pkt.haslayer(scapy.IPv6) else "N/A")
            dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[scapy.IPv6].dst if pkt.haslayer(scapy.IPv6) else "N/A")
            proto = "TCP" if pkt.haslayer(TCP) else \
                "UDP" if pkt.haslayer(UDP) else \
                    "ICMP" if pkt.haslayer(ICMP) else \
                        "ARP" if pkt.haslayer(ARP) else \
                            "IPv6" if pkt.haslayer(scapy.IPv6) else "Other"
            length = len(pkt)
            info = format_packet_info(pkt, connection_isn)

            parsed_packets.append({
                "id": idx,
                "timestamp": rel_time,
                "source": src,
                "destination": dst,
                "protocol": proto,
                "length": length,
                "info": info
            })
        except Exception as e:
            print(f"Error parsing packet {idx}: {e}")
            continue

    return parsed_packets


# Extrage informații despre pachetele capturate.
def format_packet_info(pkt, isn_map):
    try:
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 1:
                return f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"
            elif pkt[ARP].op == 2:
                return f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"

        elif pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt.sprintf("%TCP.flags%")

            fwd_key = (pkt[IP].src, src_port, pkt[IP].dst, dst_port)
            rev_key = (pkt[IP].dst, dst_port, pkt[IP].src, src_port)

            raw_seq = pkt[TCP].seq
            raw_ack = pkt[TCP].ack

            if fwd_key not in isn_map:
                isn_map[fwd_key] = raw_seq
            if rev_key not in isn_map:
                isn_map[rev_key] = raw_ack

            rel_seq = raw_seq - isn_map[fwd_key]
            rel_ack = raw_ack - isn_map.get(rev_key, raw_ack)

            win = pkt[TCP].window
            tcp_len = len(pkt[TCP].payload)

            return f"{src_port} -> {dst_port} [{flags}] Seq={rel_seq} Ack={rel_ack} Win={win} Len={tcp_len}"

        elif pkt.haslayer(UDP):
            return f"{pkt[UDP].sport} -> {pkt[UDP].dport} Len={len(pkt) - 28}"

        elif pkt.haslayer(ICMP):
            return pkt.sprintf("%ICMP.type%")

        elif pkt.haslayer(scapy.IPv6):
            return "IPv6 Packet"

        return pkt.summary()

    except Exception as e:
        return f"[Error formatting packet info: {e}]"


def get_packet_raw(pkt):
    return bytes(pkt)


# Returnează .show() pentru vizualizare structuri.
def get_packet_layers(pkt):
    return pkt.show(dump=True)


# Generează un hexdump ASCII, linie cu linie.
def hex_dump(raw_bytes):
    hex_lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i + 16]
        hex_part = ' '.join(f"{b:02X}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append(f"{i:04X}  {hex_part:<48}  {ascii_part}")
    return '\n'.join(hex_lines)
