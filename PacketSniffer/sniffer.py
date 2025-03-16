# import scapy.all as scapy
# from scapy.layers.http import HTTPRequest
# import argparse
# import psutil
# import tkinter as tk
# from tkinter import ttk
# import threading
# import socket
#
# global start_time, sniffing
# start_time = None
# sniffing = False
#
#
# def get_interface_names():
#     interfaces = psutil.net_if_addrs()
#     return {iface: iface for iface in interfaces}  # Mapping iface name to itself
#
#
# def list_interfaces():
#     interface_map = get_interface_names()
#     interfaces = list(interface_map.keys())
#     return interfaces
#
#
# def get_protocol_name(proto_number):
#     protocols = {6: "TCP", 17: "UDP", 1: "ICMP"}  # Common protocol mapping
#     return protocols.get(proto_number, str(proto_number))
#
#
# def packet_callback(packet):
#     global start_time
#     try:
#         if start_time is None:
#             start_time = packet.time  # Set the first packet's time as the reference
#
#         time = round(packet.time - start_time, 6)  # Normalize time to start from 0
#         src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
#         dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
#         length = len(packet)
#
#         # Initialize protocol and info
#         proto = "N/A"
#         info = ""
#         src_port = "N/A"
#         dst_port = "N/A"
#
#         # Check for ARP
#         if packet.haslayer(scapy.ARP):
#             proto = "ARP"
#             arp_op = packet[scapy.ARP].op
#             if arp_op == 1:  # ARP request
#                 info = f"Who has {packet[scapy.ARP].pdst}? Tell {packet[scapy.ARP].psrc}"
#             elif arp_op == 2:  # ARP reply
#                 info = f"{packet[scapy.ARP].psrc} is at {packet[scapy.ARP].hwsrc}"
#
#         # Check for TCP
#         elif packet.haslayer(scapy.TCP):
#             proto = "TCP"
#             src_port = packet[scapy.TCP].sport
#             dst_port = packet[scapy.TCP].dport
#             flags = packet.sprintf("%TCP.flags%")
#             info = f"{src_port} -> {dst_port} [{flags}]"
#
#         # Check for UDP
#         elif packet.haslayer(scapy.UDP):
#             proto = "UDP"
#             src_port = packet[scapy.UDP].sport
#             dst_port = packet[scapy.UDP].dport
#             info = f"{src_port} -> {dst_port} Len={length - 28}"
#
#         # Check for ICMP
#         elif packet.haslayer(scapy.ICMP):
#             proto = "ICMP"
#             info = packet.sprintf("%ICMP.type%")
#
#         table.insert("", tk.END, values=(time, src, dst, proto, src_port, dst_port, length, info), tags=(proto,))
#         table.yview_moveto(1)  # Auto-scroll to the latest entry
#     except Exception as e:
#         print("Error processing packet:", e)
#
#
# def start_capture(interface):
#     global sniffing, start_time
#     sniffing = True
#     start_time = None  # Reset start time on each capture
#     start_button.config(state=tk.DISABLED)  # Disable start button
#     stop_button.config(state=tk.NORMAL)  # Enable stop button
#     scapy.sniff(iface=interface, store=False, prn=packet_callback, stop_filter=lambda x: not sniffing)
#
#
# def start_sniffing():
#     global sniffing, sniff_thread
#     selected_interface = interface_var.get()
#     if selected_interface:
#         sniff_thread = threading.Thread(target=start_capture, args=(selected_interface,), daemon=True)
#         sniff_thread.start()
#
#
# def stop_sniffing():
#     global sniffing
#     sniffing = False
#     start_button.config(state=tk.NORMAL)  # Enable start button
#     stop_button.config(state=tk.DISABLED)  # Disable stop button
#
#
# def populate_interfaces():
#     interfaces = list_interfaces()
#     interface_dropdown['values'] = interfaces
#     if interfaces:
#         interface_var.set(interfaces[0])
#
#
# # GUI Setup
# root = tk.Tk()
# root.title("Packet Sniffer")
# root.geometry("1400x600")
#
# frame = ttk.Frame(root, padding="10")
# frame.pack(fill=tk.BOTH, expand=True)
#
# interface_var = tk.StringVar()
# interface_label = ttk.Label(frame, text="Select Network Interface:")
# interface_label.pack()
# interface_dropdown = ttk.Combobox(frame, textvariable=interface_var)
# interface_dropdown.pack()
# populate_interfaces()
#
# start_button = ttk.Button(frame, text="Start Capture", command=start_sniffing)
# start_button.pack()
#
# stop_button = ttk.Button(frame, text="Stop Capture", command=stop_sniffing, state=tk.DISABLED)
# stop_button.pack()
#
# # Table for displaying packet details
# table_frame = ttk.Frame(frame)
# table_frame.pack(fill=tk.BOTH, expand=True)
# columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "Info")
# table = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=lambda *args: scrollbar.set(*args))
# for col in columns:
#     table.heading(col, text=col)
#     table.column(col, anchor="center", width=120)
# table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
#
# # Add color coding
# table.tag_configure("TCP", background="lightblue")
# table.tag_configure("UDP", background="lightgreen")
# table.tag_configure("ICMP", background="lightyellow")
# table.tag_configure("ARP", background="lightpink")
#
# scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=table.yview)
# scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
# table.configure(yscrollcommand=scrollbar.set)
#
# root.mainloop()



import tkinter as tk
from tkinter import ttk, messagebox
import threading
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import psutil
import socket
import time

# Global variables
global start_time, sniffing, capture_duration
start_time = None
sniffing = False
capture_duration = 0

# Protocol mapping
def get_protocol_name(proto_number):
    protocols = {
        0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
        10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
        18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1",
        26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
        34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
        43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH",
        52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
        60: "IPv6-Opts", 61: "CFTP", 62: "SAT-EXPAK", 63: "KRYPTOLAN", 64: "RVD", 65: "IPPC", 66: "SAT-MON", 67: "VISA",
        68: "IPCV", 69: "CPNX", 70: "CPHB", 71: "WSN", 72: "PVP", 73: "BR-SAT-MON", 74: "SUN-ND", 75: "WB-MON", 76: "WB-EXPAK",
        77: "ISO-IP", 78: "VMTP", 79: "SECURE-VMTP", 80: "VINES", 81: "TTP", 82: "NSFNET-IGP", 83: "DGP", 84: "TCF", 85: "EIGRP",
        86: "OSPFIGP", 87: "Sprite-RPC", 88: "LARP", 89: "MTP", 90: "AX.25", 91: "IPIP", 92: "MICP", 93: "SCC-SP", 94: "ETHERIP",
        95: "ENCAP", 96: "GMTP", 97: "IFMP", 98: "PNNI", 99: "PIM", 100: "ARIS", 101: "SCPS", 102: "QNX", 103: "A/N", 104: "IPComp",
        105: "SNP", 106: "Compaq-Peer", 107: "IPX-in-IP", 108: "VRRP", 109: "PGM", 110: "L2TP", 111: "DDX", 112: "IATP", 113: "STP",
        114: "SRP", 115: "UTI", 116: "SMP", 117: "SM", 118: "PTP", 119: "ISIS", 120: "FIRE", 121: "CRTP", 122: "CRUDP", 123: "SSCOPMCE",
        124: "IPLT", 125: "SPS", 126: "PIPE", 127: "SCTP", 128: "FC", 129: "RSVP-E2E-IGNORE", 130: "Mobility Header", 131: "UDPLite",
        132: "MPLS-in-IP", 133: "manet", 134: "HIP", 135: "Shim6", 136: "WESP", 137: "ROHC"
    }
    return protocols.get(proto_number, str(proto_number))

# Packet callback function
def packet_callback(packet):
    global start_time
    try:
        if start_time is None:
            start_time = packet.time  # Set the first packet's time as the reference
            time = "0.000000"
        else:
            time = f"{round(packet.time - start_time, 6):.6f}" # Normalize time to start from 0
        src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
        dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
        length = len(packet)

        # Initialize protocol and info
        proto = "N/A"
        info = ""

        # Check for ARP
        if packet.haslayer(scapy.ARP):
            proto = "ARP"
            arp_op = packet[scapy.ARP].op
            if arp_op == 1:  # ARP request
                info = f"Who has {packet[scapy.ARP].pdst}? Tell {packet[scapy.ARP].psrc}"
            elif arp_op == 2:  # ARP reply
                info = f"{packet[scapy.ARP].psrc} is at {packet[scapy.ARP].hwsrc}"

        # Check for TCP
        elif packet.haslayer(scapy.TCP):
            proto = "TCP"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            flags = packet.sprintf("%TCP.flags%")
            info = f"{src_port} -> {dst_port} [{flags}]"

            # Check for TLS (TLS is encapsulated in TCP)
            if packet.haslayer(scapy.Raw):
                raw_load = packet[scapy.Raw].load
                if raw_load and raw_load[0] == 0x16:  # TLS handshake
                    proto = "TLSv1.2"
                    info = "Application Data"

        # Check for UDP
        elif packet.haslayer(scapy.UDP):
            proto = "UDP"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            info = f"{src_port} -> {dst_port} Len={length - 28}"  # UDP header is 8 bytes

            # Check for RTCP (RTCP typically uses UDP ports in the range 5004-65535)
            if dst_port >= 5004 and dst_port <= 65535:
                proto = "RTCP"
                info = "Receiver Report"

        # Check for ICMP
        elif packet.haslayer(scapy.ICMP):
            proto = "ICMP"
            info = packet.sprintf("%ICMP.type%")

        # Check for IPv6
        elif packet.haslayer(scapy.IPv6):
            proto = "IPv6"
            info = f"IPv6 Packet"

        # Insert into table
        table.insert("", tk.END, values=(time, src, dst, proto, src_port if 'src_port' in locals() else "N/A", dst_port if 'dst_port' in locals() else "N/A", length, info), tags=(proto,))
        table.yview_moveto(1)  # Auto-scroll to the latest entry

    except Exception as e:
        print("Error processing packet:", e)

# Start capture function
def start_capture(interface, duration):
    global sniffing, start_time
    sniffing = True
    start_time = None  # Reset start time on each capture
    start_button.config(state=tk.DISABLED)  # Disable start button
    stop_button.config(state=tk.NORMAL)  # Enable stop button
    if duration > 0:
        threading.Timer(duration, stop_sniffing).start()
    scapy.sniff(iface=interface, store=False, prn=packet_callback, stop_filter=lambda x: not sniffing)

# Start sniffing function
def start_sniffing():
    global sniffing, sniff_thread, capture_duration
    selected_interface = interface_var.get()
    capture_duration = int(duration_var.get())
    if selected_interface:
        sniff_thread = threading.Thread(target=start_capture, args=(selected_interface, capture_duration), daemon=True)
        sniff_thread.start()

# Stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False
    start_button.config(state=tk.NORMAL)  # Enable start button
    stop_button.config(state=tk.DISABLED)  # Disable stop button

# Populate interfaces function
def populate_interfaces():
    interfaces = list_interfaces()
    interface_dropdown['values'] = interfaces
    if interfaces:
        interface_var.set(interfaces[0])

# Get interface names
def get_interface_names():
    interfaces = psutil.net_if_addrs()
    return {iface: iface for iface in interfaces}  # Mapping iface name to itself

# List interfaces
def list_interfaces():
    interface_map = get_interface_names()
    interfaces = list(interface_map.keys())
    return interfaces

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1400x600")

frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

interface_var = tk.StringVar()
interface_label = ttk.Label(frame, text="Select Network Interface:")
interface_label.pack()
interface_dropdown = ttk.Combobox(frame, textvariable=interface_var)
interface_dropdown.pack()
populate_interfaces()

duration_var = tk.StringVar(value="0")
duration_label = ttk.Label(frame, text="Capture Duration (seconds, 0 for infinite):")
duration_label.pack()
duration_entry = ttk.Entry(frame, textvariable=duration_var)
duration_entry.pack()

start_button = ttk.Button(frame, text="Start Capture", command=start_sniffing)
start_button.pack()

stop_button = ttk.Button(frame, text="Stop Capture", command=stop_sniffing, state=tk.DISABLED)
stop_button.pack()

# Table for displaying packet details
table_frame = ttk.Frame(frame)
table_frame.pack(fill=tk.BOTH, expand=True)
columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "Info")
table = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=lambda *args: scrollbar.set(*args))
for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="center", width=120)
table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add color coding
table.tag_configure("TCP", background="lightblue")
table.tag_configure("UDP", background="lightgreen")
table.tag_configure("ICMP", background="lightyellow")
table.tag_configure("TLSv1.2", background="lightcoral")
table.tag_configure("ARP", background="lightpink")
table.tag_configure("RTCP", background="lightcyan")
table.tag_configure("IPv6", background="lightgray")

scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=table.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
table.configure(yscrollcommand=scrollbar.set)

root.mainloop()