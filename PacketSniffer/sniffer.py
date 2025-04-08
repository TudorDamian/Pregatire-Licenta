import tkinter as tk
from tkinter import ttk
import threading
import scapy.all as scapy
from scapy.all import wrpcap
import psutil
from datetime import datetime

# Global variables
global start_time, sniffing, sniff_thread, capture_duration, packet_counter


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
        68: "IPCV", 69: "CPNX", 70: "CPHB", 71: "WSN", 72: "PVP", 73: "BR-SAT-MON", 74: "SUN-ND", 75: "WB-MON",
        76: "WB-EXPAK",
        77: "ISO-IP", 78: "VMTP", 79: "SECURE-VMTP", 80: "VINES", 81: "TTP", 82: "NSFNET-IGP", 83: "DGP", 84: "TCF",
        85: "EIGRP",
        86: "OSPFIGP", 87: "Sprite-RPC", 88: "LARP", 89: "MTP", 90: "AX.25", 91: "IPIP", 92: "MICP", 93: "SCC-SP",
        94: "ETHERIP",
        95: "ENCAP", 96: "GMTP", 97: "IFMP", 98: "PNNI", 99: "PIM", 100: "ARIS", 101: "SCPS", 102: "QNX", 103: "A/N",
        104: "IPComp",
        105: "SNP", 106: "Compaq-Peer", 107: "IPX-in-IP", 108: "VRRP", 109: "PGM", 110: "L2TP", 111: "DDX", 112: "IATP",
        113: "STP",
        114: "SRP", 115: "UTI", 116: "SMP", 117: "SM", 118: "PTP", 119: "ISIS", 120: "FIRE", 121: "CRTP", 122: "CRUDP",
        123: "SSCOPMCE",
        124: "IPLT", 125: "SPS", 126: "PIPE", 127: "SCTP", 128: "FC", 129: "RSVP-E2E-IGNORE", 130: "Mobility Header",
        131: "UDPLite",
        132: "MPLS-in-IP", 133: "manet", 134: "HIP", 135: "Shim6", 136: "WESP", 137: "ROHC"
    }
    return protocols.get(proto_number, str(proto_number))


# Global dictionary to store ISN for each connection
connection_isn = {}

# Captured packages list for saving
captured_packets = []


# Packet callback function
def packet_callback(packet):
    global start_time, packet_counter, connection_isn
    try:
        if start_time is None:
            start_time = packet.time  # Set the first packet's time as the reference
            time = "0.000000"
        else:
            time = f"{round(packet.time - start_time, 6):.6f}"  # Normalize time to start from 0

        packet_counter += 1  # Increment packet index
        # Extract source and destination IPs, supporting both IPv4 and IPv6
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
        elif packet.haslayer(scapy.IPv6):
            src = packet[scapy.IPv6].src
            dst = packet[scapy.IPv6].dst
        else:
            src = "N/A"
            dst = "N/A"
        length = len(packet)

        # Initialize protocol and info
        proto = "N/A"
        info = ""
        src_port = "N/A"
        dst_port = "N/A"

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

            # Extract TCP flags
            flags = []
            flag_dict = {
                0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
                0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR"
            }

            for flag, name in flag_dict.items():
                if packet[scapy.TCP].flags & flag:
                    flags.append(name)

            flags_str = ", ".join(flags)  # Format flags as a comma-separated list

            # Get raw sequence and acknowledgment numbers
            raw_seq = packet[scapy.TCP].seq
            raw_ack = packet[scapy.TCP].ack

            # Define a connection key (src, src_port, dst, dst_port) for tracking ISNs
            fwd_key = (src, src_port, dst, dst_port)
            rev_key = (dst, dst_port, src, src_port)  # Reverse direction for ACK tracking

            # Store ISN for both directions
            if fwd_key not in connection_isn:
                connection_isn[fwd_key] = raw_seq  # Store ISN for sender

            if rev_key not in connection_isn:
                connection_isn[rev_key] = raw_ack  # Store ISN for receiver's acknowledgment

            # Calculate relative sequence and acknowledgment numbers
            relative_seq = raw_seq - connection_isn[fwd_key]
            relative_ack = raw_ack - connection_isn.get(rev_key, raw_ack)  # Use ISN for receiver

            # Extract window size and TCP payload length
            win = packet[scapy.TCP].window
            tcp_len = len(packet[scapy.TCP].payload)  # Length of TCP payload

            # Properly format the info string
            info = f"{src_port} -> {dst_port} [{flags_str}] Seq={relative_seq} Ack={relative_ack} Win={win} Len={tcp_len}"

        # Check for UDP
        elif packet.haslayer(scapy.UDP):
            proto = "UDP"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            info = f"{src_port} -> {dst_port} Len={length - 28}"

        # Check for ICMP
        elif packet.haslayer(scapy.ICMP):
            proto = "ICMP"
            info = packet.sprintf("%ICMP.type%")

        # Check for IPv6
        elif packet.haslayer(scapy.IPv6):
            proto = "IPv6"
            info = f"IPv6 Packet"

        captured_packets.append(packet)

        # Insert the packet details into the table
        table.insert("", tk.END, values=(packet_counter, time, src, dst, proto, length, info), tags=(proto,))
        table.yview_moveto(1)  # Auto-scroll to the latest entry

    except Exception as e:
        print("Error processing packet:", e)


def show_packet_details(event):
    selected = table.focus()
    if not selected:
        return
    index = int(table.item(selected)['values'][0]) - 1
    if 0 <= index < len(captured_packets):
        pkt = captured_packets[index]

        # === New window for package details ===
        detail_win = tk.Toplevel(root)
        detail_win.title(f"Packet #{index + 1} Details")
        detail_win.geometry("1000x600")

        # === Notebook pentru tab-uri ===
        notebook = ttk.Notebook(detail_win)
        notebook.pack(fill=tk.BOTH, expand=True)

        # === Tab 1: Layered view ===
        layer_frame = tk.Frame(notebook)
        notebook.add(layer_frame, text="Packet Info")

        layer_text = tk.Text(layer_frame, wrap=tk.NONE, font=("Consolas", 10))
        layer_text.pack(fill=tk.BOTH, expand=True)

        layer_scroll_y = tk.Scrollbar(layer_frame, orient=tk.VERTICAL, command=layer_text.yview)
        layer_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        layer_text.config(yscrollcommand=layer_scroll_y.set)

        layer_scroll_x = tk.Scrollbar(layer_frame, orient=tk.HORIZONTAL, command=layer_text.xview)
        layer_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        layer_text.config(xscrollcommand=layer_scroll_x.set)

        layer_text.insert(tk.END, pkt.show(dump=True))

        # === Tab 2: Hex view ===
        hex_frame = tk.Frame(notebook)
        notebook.add(hex_frame, text="Hex View")

        hex_text = tk.Text(hex_frame, wrap=tk.NONE, font=("Courier", 10))
        hex_text.pack(fill=tk.BOTH, expand=True)

        hex_scroll_y = tk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=hex_text.yview)
        hex_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        hex_text.config(yscrollcommand=hex_scroll_y.set)

        hex_scroll_x = tk.Scrollbar(hex_frame, orient=tk.HORIZONTAL, command=hex_text.xview)
        hex_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        hex_text.config(xscrollcommand=hex_scroll_x.set)

        raw_bytes = bytes(pkt)
        hex_dump = ""
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i + 16]
            hex_part = ' '.join(f"{b:02X}" for b in chunk)
            ascii_part = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
            hex_dump += f"{i:04X}  {hex_part:<48}  {ascii_part}\n"
        hex_text.insert(tk.END, hex_dump)

        # === Export to PCAP button ===
        def export_packet():
            filename = f"packet_{index + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            wrpcap(filename, pkt)
            export_btn.config(text=f"Exported to {filename}", state=tk.DISABLED)

        export_btn = tk.Button(detail_win, text="💾 Export as .pcap", command=export_packet)
        export_btn.pack(pady=5)


def export_all_packets():
    if not captured_packets:
        print("No packets to export.")
        return
    filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    try:
        wrpcap(filename, captured_packets)
        toolbar_export_all_btn.config(text=f"Exported to {filename}", state=tk.DISABLED)
    except Exception as e:
        print(f"Export failed: {e}")


# Start capture function
def start_capture(interface, duration):
    global sniffing, start_time, packet_counter
    sniffing = True
    start_time = None
    packet_counter = 0

    toolbar_start_btn.config(state=tk.DISABLED)
    toolbar_stop_btn.config(state=tk.NORMAL)

    user_filter = filter_var.get().strip()
    if user_filter.lower().startswith("apply"):
        user_filter = ""

    if duration > 0:
        threading.Timer(duration, stop_sniffing).start()

    try:
        scapy.sniff(
            iface=interface,
            store=False,
            prn=packet_callback,
            stop_filter=lambda x: not sniffing,
            filter=user_filter
        )
    except Exception as e:
        print(f"Error when applying filter: {e}")


# Start sniffing function
def start_sniffing():
    global sniffing, sniff_thread, capture_duration
    selected_interface = interface_var.get()
    capture_duration = 0  # Always infinite
    if selected_interface:
        clear_table()  # Clear the table before starting a new capture
        sniff_thread = threading.Thread(target=start_capture, args=(selected_interface, capture_duration), daemon=True)
        sniff_thread.start()
        toolbar_start_btn.config(state=tk.DISABLED)
        toolbar_stop_btn.config(state=tk.NORMAL)
        toolbar_export_all_btn.config(text="💾 Export to .pcap", state=tk.NORMAL)


# Stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False
    toolbar_start_btn.config(state=tk.NORMAL)
    toolbar_stop_btn.config(state=tk.DISABLED)


# Clear table function
def clear_table():
    for row in table.get_children():
        table.delete(row)


# Populate interfaces function
def populate_interfaces():
    interfaces = list_interfaces()
    toolbar_interface_dropdown['values'] = interfaces
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


# --------------------------------------------  GUI SETUP  --------------------------------------------
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1210x710")

# === Toolbar Frame (up) ===
toolbar = ttk.Frame(root, padding=5)
toolbar.pack(side=tk.TOP, fill=tk.X)

# START button
toolbar_start_btn = ttk.Button(toolbar, text="▶ Start", command=start_sniffing)
toolbar_start_btn.pack(side=tk.LEFT, padx=2)

# STOP button
toolbar_stop_btn = ttk.Button(toolbar, text="■ Stop", command=stop_sniffing, state=tk.DISABLED)
toolbar_stop_btn.pack(side=tk.LEFT, padx=2)


# RESTART button
def restart_capture():
    stop_sniffing()
    start_sniffing()


toolbar_restart_btn = ttk.Button(toolbar, text="↻ Restart", command=restart_capture)
toolbar_restart_btn.pack(side=tk.LEFT, padx=2)

# Interface dropdown
interface_var = tk.StringVar()
toolbar_interface_label = ttk.Label(toolbar, text="  Network Interface:")
toolbar_interface_label.pack(side=tk.LEFT, padx=(20, 2))

toolbar_interface_dropdown = ttk.Combobox(toolbar, textvariable=interface_var, width=20)
toolbar_interface_dropdown.pack(side=tk.LEFT)

toolbar_export_all_btn = ttk.Button(toolbar, text="💾 Export to .pcap", command=export_all_packets)
toolbar_export_all_btn.pack(side=tk.RIGHT)

populate_interfaces()

# === Display Filter Frame (under toolbar) ===
filter_frame = ttk.Frame(root, padding=(10, 0))
filter_frame.pack(fill=tk.X)

filter_var = tk.StringVar()
filter_entry = ttk.Entry(filter_frame, textvariable=filter_var, font=("Consolas", 10), foreground="gray")
filter_entry.insert(0, "Apply a display filter ... <<Ctrl+/>>")
filter_entry.pack(fill=tk.X, padx=2, pady=5)


# === Placeholder logic ===
def on_entry_click(event):
    if filter_entry.get() == "Apply a display filter ... <<Ctrl+/>>":
        filter_entry.delete(0, tk.END)
        filter_entry.config(foreground="black")


def on_focusout(event):
    if not filter_entry.get():
        filter_entry.insert(0, "Apply a display filter ... <<Ctrl+/>>")
        filter_entry.config(foreground="gray")


filter_entry.bind("<FocusIn>", on_entry_click)
filter_entry.bind("<FocusOut>", on_focusout)

# === Trigger for starting capturing when pressing Enter ===
filter_entry.bind("<Return>", lambda event: start_sniffing())

# === Main frame (for tabel) ===
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

# === Tabel for displaying packages ===
table_frame = ttk.Frame(frame)
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
table.tag_configure("TCP", background="lightblue")
table.tag_configure("UDP", background="lightgreen")
table.tag_configure("ICMP", background="lightyellow")
table.tag_configure("TLSv1.2", background="lightcoral")
table.tag_configure("ARP", background="lightpink")
table.tag_configure("RTCP", background="lightcyan")
table.tag_configure("IPv6", background="lightgray")

# === Start GUI loop ===
root.mainloop()
