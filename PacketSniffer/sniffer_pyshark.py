import tkinter as tk
from tkinter import ttk
import pyshark
import threading
import json
import os
from datetime import datetime
import psutil
import asyncio

captured_packets = []
packet_counter = 0
sniffing = False
EXPORT_DIR = "./captures_parsed"

os.makedirs(EXPORT_DIR, exist_ok=True)


def packet_to_dict(pkt):
    pkt_dict = {
        "timestamp": pkt.sniff_timestamp,
        "length": pkt.length,
        "highest_layer": pkt.highest_layer,
        "layers": {}
    }

    for layer in pkt.layers:
        layer_name = layer.layer_name
        pkt_dict["layers"][layer_name] = {}
        for field_line in layer._all_fields.items():
            field, value = field_line
            pkt_dict["layers"][layer_name][field] = value

    return pkt_dict


def show_packet_details():
    return


# Export all captures into a .pcap file
def export_all_packets():
    return


def format_info(packet):
    try:
        if 'TCP' in packet:
            flags = packet.tcp.flags
            flag_str = []
            if '0x00000002' in flags.showname: flag_str.append('SYN')
            if '0x00000010' in flags.showname: flag_str.append('ACK')
            if '0x00000001' in flags.showname: flag_str.append('FIN')
            if '0x00000004' in flags.showname: flag_str.append('RST')
            if '0x00000008' in flags.showname: flag_str.append('PSH')

            return (f"{packet.tcp.srcport} → {packet.tcp.dstport} [{', '.join(flag_str)}] Seq={packet.tcp.seq} "
                    f"Ack={packet.tcp.ack} Win={packet.tcp.window_size_value} Len={packet.length}")

        elif 'UDP' in packet:
            return f"{packet.udp.srcport} → {packet.udp.dstport} Len={packet.length}"

        elif 'ICMP' in packet:
            return packet.icmp.type_showname

        elif 'ARP' in packet:
            if hasattr(packet.arp, 'opcode'):
                if packet.arp.opcode == '1':
                    return f"Who has {packet.arp.dst_proto_ipv4}? Tell {packet.arp.src_proto_ipv4}"
                elif packet.arp.opcode == '2':
                    return f"{packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"

        elif 'MDNS' in packet:
            return f"Multicast DNS Query/Response"

        elif 'TLS' in packet:
            return "TLS Record"

        elif 'DNS' in packet:
            return f"{packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'DNS Response'}"

        return packet.highest_layer
    except Exception as e:
        return "Info unavailable"


# Start capture function
def start_capture(interface):
    global sniffing, packet_counter
    asyncio.set_event_loop(asyncio.new_event_loop())
    sniffing = True
    packet_counter = 0
    start_time = None

    toolbar_start_btn.config(state=tk.DISABLED)
    toolbar_stop_btn.config(state=tk.NORMAL)

    capture = pyshark.LiveCapture(interface=interface)
    try:
        for packet in capture.sniff_continuously():
            if not sniffing:
                break
            if start_time is None:
                start_time = float(packet.sniff_timestamp)
            try:
                packet_counter += 1
                elapsed_time = float(packet.sniff_timestamp) - start_time
                time_str = f"{elapsed_time:.6f}"
                src = getattr(packet.ip, 'src', 'N/A') if 'IP' in packet else 'N/A'
                dst = getattr(packet.ip, 'dst', 'N/A') if 'IP' in packet else 'N/A'
                transport_proto = packet.transport_layer or "OTHER"
                if packet.highest_layer == "DATA":
                    app_proto = "UDP"
                else:
                    app_proto = packet.highest_layer
                length = packet.length

                proto_tag = transport_proto.upper() if transport_proto.upper() in ["TCP", "UDP", "ICMP", "ARP", "RTCP",
                                                                                   "HTTP", "TLS", "DNS", "IPv6"] else ""

                info = format_info(packet)

                table.insert("", tk.END, values=(packet_counter, time_str, src, dst, app_proto, length, info),
                             tags=(proto_tag,))
                table.yview_moveto(1)

                ts = float(packet.sniff_timestamp)
                filename = f"{EXPORT_DIR}/packet_{packet_counter}_{str(ts).replace('.', '_')}.json"
                pkt_json = packet_to_dict(packet)
                with open(filename, "w") as f:
                    json.dump(pkt_json, f, indent=2)

            except Exception as e:
                print(f"Packet error: {e}")
    finally:
        capture.close()


# Populate interfaces function
def populate_interfaces():
    interfaces = list_interfaces()
    interface_dropdown['values'] = interfaces
    if interfaces:
        interface_var.set(interfaces[0])


# Get interface names
def get_interface_names():
    interfaces = psutil.net_if_addrs()
    return {iface: iface for iface in interfaces}


# List interfaces
def list_interfaces():
    interface_map = get_interface_names()
    interfaces = list(interface_map.keys())
    return interfaces

# Start sniffing function
def start_sniffing():
    iface = interface_var.get()
    if iface:
        clear_table()
        threading.Thread(target=start_capture, args=(iface,), daemon=True).start()
        toolbar_start_btn.config(state=tk.DISABLED)
        toolbar_stop_btn.config(state=tk.NORMAL)


# Stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False
    toolbar_start_btn.config(state=tk.NORMAL)
    toolbar_stop_btn.config(state=tk.DISABLED)


# Restart sniffing function
def restart_capture():
    stop_sniffing()
    # user_filter = filter_var.get().strip()
    # if user_filter.lower().startswith("apply"):
    #     filter_var.set("")
    start_sniffing()


# Clear table function
def clear_table():
    for row in table.get_children():
        table.delete(row)


# --------------------------------------------  GUI SETUP  --------------------------------------------
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1210x710")

# === Toolbar Frame (up) ===
toolbar = ttk.Frame(root, padding=5)
toolbar.pack(side=tk.TOP, fill=tk.X)

# Interface dropdown
interface_var = tk.StringVar()
ttk.Label(toolbar, text="Network Interface:").pack(side=tk.LEFT, padx=(20, 2))
interface_dropdown = ttk.Combobox(toolbar, textvariable=interface_var, width=20)
interface_dropdown.pack(side=tk.LEFT)
populate_interfaces()

# === EXPORT button ===
toolbar_export_all_btn = ttk.Button(toolbar, text="💾 Export to .pcap", command=export_all_packets)
toolbar_export_all_btn.pack(side=tk.RIGHT, padx= 10)

# === START button ===
toolbar_start_btn = ttk.Button(toolbar, text="▶ Start", command=start_sniffing)
toolbar_start_btn.pack(side=tk.LEFT, padx=2)

# === STOP button ===
toolbar_stop_btn = ttk.Button(toolbar, text="■ Stop", command=stop_sniffing, state=tk.DISABLED)
toolbar_stop_btn.pack(side=tk.LEFT, padx=2)

# === RESTART button ===
toolbar_restart_btn = ttk.Button(toolbar, text="↻ Restart", command=restart_capture)
toolbar_restart_btn.pack(side=tk.LEFT, padx=2)

# === Tabel for displaying packages ===
table_frame = ttk.Frame(root)
table_frame.pack(fill=tk.BOTH, expand=True)

columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
table = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=lambda *args: scrollbar.set(*args))
table.bind("<Double-1>", show_packet_details)
for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="center", width=120)
table.column("Info", anchor="w", width=300)
table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# === Scrollbar ===
scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=table.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
table.configure(yscrollcommand=scrollbar.set)

# === Color tags for protocols ===
table.tag_configure("TCP", background="#CCE5FF")       # light blue
table.tag_configure("UDP", background="#D4EDDA")       # light green
table.tag_configure("ICMP", background="#FFF3CD")      # light yellow
table.tag_configure("ARP", background="#F8D7DA")       # light pink
table.tag_configure("HTTP", background="#B17F59")       # light brown
table.tag_configure("RTCP", background="#D1ECF1")      # light cyan
table.tag_configure("TLS", background="#F08080")       # light grey
table.tag_configure("DNS", background="#E8D3FF")       # light purple
table.tag_configure("IPv6", background="#F5F5F5")      # neutral gray

# === Start GUI loop ===s
root.mainloop()
