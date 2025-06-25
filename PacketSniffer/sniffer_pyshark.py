import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import pyshark
import threading
import json
import os
from datetime import datetime
import psutil
import asyncio
import queue

captured_packets = []
packet_counter = 0
sniffing = False
start_time = None
last_pcap_path = None
packet_queue = queue.Queue()
packet_map = {}

EXPORT_PCAP_DIR = "./captures_exported_pcapng"

os.makedirs(EXPORT_PCAP_DIR, exist_ok=True)


def packet_to_dict(pkt):
    pkt_dict = {
        "timestamp": pkt.sniff_time.isoformat() + "Z",
        "length": pkt.length,
        "highest_layer": pkt.highest_layer,
    }

    for layer in pkt.layers:
        for field, value in layer._all_fields.items():
            if not field or "_raw" in field:
                continue
            try:
                flat_field = field.replace(".", "_")
                pkt_dict[flat_field] = str(value)
            except Exception:
                pass

    return pkt_dict


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
    global sniffing, packet_counter, start_time, last_pcap_path
    asyncio.set_event_loop(asyncio.new_event_loop())
    sniffing = True
    packet_counter = 0
    start_time = None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    last_pcap_path = os.path.join(EXPORT_PCAP_DIR, f"live_capture_{timestamp}.pcapng")
    capture = pyshark.LiveCapture(interface=interface, output_file=last_pcap_path)
    # capture = pyshark.LiveCapture(interface=interface, output_file=last_pcap_path, use_json=True, include_raw=True)

    toolbar_start_btn.config(state=tk.DISABLED)
    toolbar_stop_btn.config(state=tk.NORMAL)

    try:
        for packet in capture.sniff_continuously():
            if not sniffing:
                break
            packet_queue.put(packet)
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture.close()


# Process queue of the captures
def process_queue():
    global packet_counter, start_time
    max_packets = 800

    # while not packet_queue.empty():
    for _ in range(max_packets):
        if packet_queue.empty():
            break
        packet = packet_queue.get()
        try:
            if start_time is None:
                start_time = float(packet.sniff_timestamp)

            packet_counter += 1
            elapsed_time = float(packet.sniff_timestamp) - start_time
            time_str = f"{elapsed_time:.6f}"

            if 'IP' in packet:
                src = getattr(packet.ip, 'src', 'N/A')
                dst = getattr(packet.ip, 'dst', 'N/A')
            else:
                try:
                    src = f"{packet.eth.src_oui_resolved} ({packet.eth.src})"
                except:
                    src = getattr(packet.eth, 'src', 'N/A')
                try:
                    dst = f"{packet.eth.dst_oui_resolved} ({packet.eth.dst})"
                except:
                    dst = getattr(packet.eth, 'dst', 'N/A')

            transport_proto = packet.transport_layer or "OTHER"
            app_proto = "UDP" if packet.highest_layer == "DATA" else packet.highest_layer
            length = packet.length
            proto_tag = transport_proto.upper() if transport_proto.upper() in [
                "TCP", "UDP", "ICMP", "ARP", "RTCP", "HTTP", "TLS", "DNS", "IPv6"] else ""
            info = format_info(packet)

            table.insert("", tk.END, values=(packet_counter, time_str, src, dst, app_proto, length, info),
                         tags=(proto_tag,))
            table.yview_moveto(1)

            captured_packets.append(packet)

            packet._gui_index = packet_counter
            packet_map[packet_counter] = packet

        except Exception as e:
            print(f"[ERROR] Processing packet #{packet_counter}: {e}")

    if packet_queue.qsize() > 0:
        print(f"[INFO] Queue backlog: {packet_queue.qsize()} packets remaining.")

    root.after(10, process_queue)


# Process packets left after stopping the capture
def process_packet(packet):
    global packet_counter, start_time
    try:
        if start_time is None:
            start_time = float(packet.sniff_timestamp)

        packet_counter += 1
        elapsed_time = float(packet.sniff_timestamp) - start_time
        time_str = f"{elapsed_time:.6f}"

        if 'IP' in packet:
            src = getattr(packet.ip, 'src', 'N/A')
            dst = getattr(packet.ip, 'dst', 'N/A')
        else:
            try:
                src = f"{packet.eth.src_oui_resolved} ({packet.eth.src})"
            except:
                src = getattr(packet.eth, 'src', 'N/A')
            try:
                dst = f"{packet.eth.dst_oui_resolved} ({packet.eth.dst})"
            except:
                dst = getattr(packet.eth, 'dst', 'N/A')

        transport_proto = packet.transport_layer or "OTHER"
        app_proto = "UDP" if packet.highest_layer == "DATA" else packet.highest_layer
        length = packet.length
        proto_tag = transport_proto.upper() if transport_proto.upper() in [
            "TCP", "UDP", "ICMP", "ARP", "RTCP", "HTTP", "TLS", "DNS", "IPv6"] else ""
        info = format_info(packet)

        table.insert("", tk.END, values=(packet_counter, time_str, src, dst, app_proto, length, info),
                     tags=(proto_tag,))
        table.yview_moveto(1)

        captured_packets.append(packet)

        packet._gui_index = packet_counter
        packet_map[packet_counter] = packet

    except Exception as e:
        print(f"[ERROR] Finalizing packet #{packet_counter}: {e}")


# Export all captures into a .pcapng file
def export_all_packets_pcapng():
    if last_pcap_path and os.path.exists(last_pcap_path):
        print(f"PCAP already saved to: {last_pcap_path}")
    else:
        print("No PCAP file was created.")


# Export all captures into a .json file
def export_all_packets_json1():
    if not captured_packets:
        print("No packets to export.")
        return

    filename = f"./captures_exported_json/capture_json_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    export_list = [packet_to_dict(pkt) for pkt in captured_packets]
    try:
        with open(filename, "w") as f:
            json.dump(export_list, f, indent=2)
        print(f"Exported JSON to: {filename}")
    except Exception as e:
        print(f"Failed to export JSON: {e}")


def export_all_packets_json():
    if not captured_packets:
        print("No packets to export.")
        return

    filename = f"./elk/captures/pcap_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    try:
        with open(filename, "w") as f:
            for pkt in captured_packets:
                pkt_dict = packet_to_dict(pkt)
                f.write(json.dumps(pkt_dict) + "\n")
        print(f"Exported JSON Lines to: {filename}")
    except Exception as e:
        print(f"Failed to export JSON: {e}")


# Upload .pcapng file
def upload_pcapng_file():
    file_path = filedialog.askopenfilename(
        filetypes=[("PCAPNG files", "*.pcapng"), ("All files", "*.*")]
    )
    if not file_path:
        return

    clear_table()
    captured_packets.clear()
    global packet_counter, start_time
    packet_counter = 0
    start_time = None

    try:
        capture = pyshark.FileCapture(file_path)
        # capture = pyshark.FileCapture(file_path, use_json=True, include_raw=True)
        for packet in capture:
            process_packet(packet)
        capture.close()
        print(f"[INFO] Finished loading {file_path}")
    except Exception as e:
        print(f"[ERROR] Could not load file: {e}")


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
        captured_packets.clear()
        threading.Thread(target=start_capture, args=(iface,), daemon=True).start()
        toolbar_start_btn.config(state=tk.DISABLED)
        toolbar_stop_btn.config(state=tk.NORMAL)


# Stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False
    toolbar_start_btn.config(state=tk.NORMAL)
    toolbar_stop_btn.config(state=tk.DISABLED)

    while not packet_queue.empty():
        process_packet(packet_queue.get())


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


def show_packet_details(event=None):
    selected = table.focus()
    if not selected:
        return

    values = table.item(selected, "values")
    if not values:
        return

    try:
        pkt_index = int(values[0])
        packet = packet_map.get(pkt_index)
        if not packet:
            print("[WARN] Packet not found for index:", pkt_index)
            return

        # === Create new window ===
        detail_win = tk.Toplevel(root)
        detail_win.title(f"Packet #{pkt_index} Details")
        detail_win.geometry("1210x710")

        # === Notebook (tab view) ===
        notebook = ttk.Notebook(detail_win)
        notebook.pack(fill=tk.BOTH, expand=True)

        # === Tab 1: Layer View ===
        layer_frame = ttk.Frame(notebook)
        notebook.add(layer_frame, text="Layers View")

        layer_scroll_y = ttk.Scrollbar(layer_frame, orient=tk.VERTICAL)

        text_area = tk.Text(
            layer_frame,
            wrap="word",
            yscrollcommand=layer_scroll_y.set
        )
        text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        layer_scroll_y.config(command=text_area.yview)
        layer_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        layer_titles = {
            "eth": "Ethernet II",
            "ip": "Internet Protocol",
            "tcp": "Transmission Control Protocol",
            "udp": "User Datagram Protocol",
            "arp": "Address Resolution Protocol",
            "dns": "Domain Name System",
            "tls": "Transport Layer Security",
            "http": "HyperText Transfer Protocol",
            "quic": "Quick UDP Internet Connections"
        }

        for layer in packet.layers:
            layer_name = layer.layer_name
            label = layer_titles.get(layer_name, layer_name.upper())
            text_area.insert(tk.END, f"▶ {label}\n")

            for field in layer._all_fields:
                try:
                    value = getattr(layer, field).showname
                except Exception:
                    value = layer._all_fields.get(field)
                text_area.insert(tk.END, f"   {value}\n")

            text_area.insert(tk.END, "\n")

        text_area.config(state=tk.DISABLED)

        # === Tab 2: Hex View ===
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex View")

        hex_text = tk.Text(hex_frame, wrap="none", font=("Courier", 9))
        hex_text.pack(fill=tk.BOTH, expand=True)

        try:
            if hasattr(packet, "get_raw_packet"):
                raw_bytes = bytes.fromhex(packet.get_raw_packet().hex())
            elif hasattr(packet, "get_raw_packet_bytes"):
                raw_bytes = packet.get_raw_packet_bytes()
            else:
                raise Exception("Raw data not available.")

            hex_lines = []
            ascii_lines = []
            for i in range(0, len(raw_bytes), 16):
                chunk = raw_bytes[i:i + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
                ascii_lines.append(ascii_part)

            hex_text.insert("1.0", "\n".join(hex_lines))

        except Exception as e:
            hex_text.insert("1.0", f"[Error getting raw packet]\n{e}")


    except Exception as e:
        print(f"[ERROR] show_packet_details: {e}")


# ============================================  GUI SETUP  ============================================
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1210x710")
root.iconbitmap("./assets/icon.ico")

# === Toolbar Frame ===
toolbar = ttk.Frame(root, padding=5)
toolbar.pack(side=tk.TOP, fill=tk.X)

# Interface dropdown
interface_var = tk.StringVar()
ttk.Label(toolbar, text="Network Interface:").pack(side=tk.LEFT, padx=(20, 2))
interface_dropdown = ttk.Combobox(toolbar, textvariable=interface_var, width=20)
interface_dropdown.pack(side=tk.LEFT)
populate_interfaces()

# === EXPORT .pcap button ===
toolbar_export_pcap_btn = ttk.Button(toolbar, text="📂 Upload .pcapng", command=upload_pcapng_file)
toolbar_export_pcap_btn.pack(side=tk.RIGHT, padx=10)

# === EXPORT .json button ===
toolbar_export_json_btn = ttk.Button(toolbar, text="💾 Export to .json", command=export_all_packets_json)
toolbar_export_json_btn.pack(side=tk.RIGHT, padx=2)

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
table.tag_configure("TCP", background="#CCE5FF")  # light blue
table.tag_configure("UDP", background="#D4EDDA")  # light green
table.tag_configure("ICMP", background="#FFF3CD")  # light yellow
table.tag_configure("ARP", background="#F8D7DA")  # light pink
table.tag_configure("HTTP", background="#B17F59")  # light brown
table.tag_configure("RTCP", background="#D1ECF1")  # light cyan
table.tag_configure("TLS", background="#F08080")  # light grey
table.tag_configure("DNS", background="#E8D3FF")  # light purple
table.tag_configure("IPv6", background="#F5F5F5")  # neutral gray

# === Start processing queue every 50ms ===
root.after(10, process_queue)

# === Start GUI loop ===s
root.mainloop()
