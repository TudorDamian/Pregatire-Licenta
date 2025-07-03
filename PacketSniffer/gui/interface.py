import tkinter as tk
from tkinter import ttk, filedialog
import os


def show_packet_details(table, packet_map, root):
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

        detail_win = tk.Toplevel(root)
        detail_win.title(f"Packet #{pkt_index} Details")
        detail_win.geometry("1210x710")

        notebook = ttk.Notebook(detail_win)
        notebook.pack(fill=tk.BOTH, expand=True)

        layer_frame = ttk.Frame(notebook)
        notebook.add(layer_frame, text="Layers View")

        layer_scroll_y = ttk.Scrollbar(layer_frame, orient=tk.VERTICAL)
        text_area = tk.Text(layer_frame, wrap="word", yscrollcommand=layer_scroll_y.set)
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


def setup_gui(start_callback, stop_callback, restart_callback, export_json_callback, upload_pcap_callback,
              view_graphs_callback, show_details_callback):
    root = tk.Tk()
    root.title("Packet Sniffer")
    root.geometry("1210x710")
    ico_path = os.path.join(os.path.dirname(__file__), '../assets/icon.ico')
    root.iconbitmap(default=ico_path)

    toolbar = ttk.Frame(root, padding=5)
    toolbar.pack(side=tk.TOP, fill=tk.X)

    interface_var = tk.StringVar()
    ttk.Label(toolbar, text="Network Interface:").pack(side=tk.LEFT, padx=(20, 2))
    interface_dropdown = ttk.Combobox(toolbar, textvariable=interface_var, width=20)
    interface_dropdown.pack(side=tk.LEFT)

    toolbar_export_pcap_btn = ttk.Button(toolbar, text="📂 Upload .pcapng", command=upload_pcap_callback)
    toolbar_export_pcap_btn.pack(side=tk.RIGHT, padx=10)

    toolbar_export_json_btn = ttk.Button(toolbar, text="💾 Export to .json", command=export_json_callback)
    toolbar_export_json_btn.pack(side=tk.RIGHT, padx=5)

    toolbar_export_json_btn = ttk.Button(toolbar, text="📊 View Graphs", command=view_graphs_callback)
    toolbar_export_json_btn.pack(side=tk.RIGHT, padx=5)

    toolbar_start_btn = ttk.Button(toolbar, text="▶ Start", command=start_callback)
    toolbar_start_btn.pack(side=tk.LEFT, padx=2)

    toolbar_stop_btn = ttk.Button(toolbar, text="■ Stop", command=stop_callback, state=tk.DISABLED)
    toolbar_stop_btn.pack(side=tk.LEFT, padx=2)

    toolbar_restart_btn = ttk.Button(toolbar, text="↻ Restart", command=restart_callback)
    toolbar_restart_btn.pack(side=tk.LEFT, padx=2)

    filter_var = tk.StringVar()
    ttk.Label(toolbar, text="🔍 Display Filter:").pack(side=tk.LEFT, padx=(20, 2))
    filter_entry = ttk.Entry(toolbar, textvariable=filter_var, width=40)
    filter_entry.pack(side=tk.LEFT, padx=(0, 10))

    table_frame = ttk.Frame(root)
    table_frame.pack(fill=tk.BOTH, expand=True)
    columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
    table = ttk.Treeview(table_frame, columns=columns, show="headings")
    table.bind("<Double-1>", show_details_callback)
    for col in columns:
        table.heading(col, text=col)
        table.column(col, anchor="center", width=120)
    table.column("Info", anchor="w", width=300)
    table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=table.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    table.configure(yscrollcommand=scrollbar.set)

    table.tag_configure("TCP", background="#CCE5FF")   # light blue
    table.tag_configure("UDP", background="#D4EDDA")   # light green
    table.tag_configure("ICMP", background="#FFF3CD")  # light yellow
    table.tag_configure("ARP", background="#F8D7DA")   # light pink
    table.tag_configure("HTTP", background="#B17F59")  # light brown
    table.tag_configure("RTCP", background="#D1ECF1")  # light cyan
    table.tag_configure("TLS", background="#F08080")   # light grey
    table.tag_configure("DNS", background="#E8D3FF")   # light purple
    table.tag_configure("IPv6", background="#F5F5F5")  # neutral gray
    table.tag_configure("QUIC", background="#D6D9E4")  # gray
    table.tag_configure("MDNS", background="#E2F0CB")  # light lime
    table.tag_configure("NBNS", background="#F9D4FF")  # very ligh purple
    table.tag_configure("SSDP", background="#DCF5FC")  # ligh cyan

    return root, interface_var, interface_dropdown, toolbar_start_btn, toolbar_stop_btn, table, filter_var, filter_entry
