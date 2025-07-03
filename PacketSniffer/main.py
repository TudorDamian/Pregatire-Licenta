import queue
import re
from capture.packet_capture import populate_interfaces, start_sniffing, stop_sniffing, restart_capture
from processing.packet_processor import process_queue, process_packet
from file_manager.packet_export import export_all_packets_json, view_graphs
from gui.interface import setup_gui, show_packet_details

# === Globals ===
captured_packets = []
packet_queue = queue.Queue()
packet_map = {}
start_time_ref = [None]
packet_counter_ref = [0]
table_data_map = {}


def clear_table():
    for row in table.get_children():
        table.delete(row)


def start_callback():
    start_sniffing(interface_var, clear_table, captured_packets, packet_queue, start_btn, stop_btn)

    root.after(10, lambda: process_queue(
        packet_queue, table, captured_packets, packet_map, root,
        format_info, start_time_ref, packet_counter_ref, table_data_map
    ))


def stop_callback():
    stop_sniffing(lambda pkt: process_packet(pkt, table, captured_packets, packet_map, format_info, start_time_ref,
                                             packet_counter_ref, table_data_map), stop_btn, start_btn)


def restart_callback():
    restart_capture(lambda: start_callback(), lambda: stop_callback())


def upload_pcap_callback():
    from tkinter import filedialog
    import pyshark
    file_path = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng"), ("All files", "*.*")])
    if not file_path:
        return

    clear_table()
    captured_packets.clear()
    packet_counter_ref[0] = 0
    start_time_ref[0] = None

    try:
        capture = pyshark.FileCapture(file_path)
        for packet in capture:
            process_packet(packet, table, captured_packets, packet_map, format_info, start_time_ref,
                           packet_counter_ref, table_data_map)
        capture.close()
        print(f"[INFO] Finished loading {file_path}")
    except Exception as e:
        print(f"[ERROR] Could not load file: {e}")


def view_graphs_callback():
    view_graphs(captured_packets)


def export_json_callback():
    export_all_packets_json(captured_packets)


def show_details_callback(event=None):
    show_packet_details(table, packet_map, root)


def format_info(packet):
    try:
        if 'TCP' in packet:
            if 'TLS' in packet:
                return "Application Data"

            elif 'DNS' in packet:
                try:
                    fields = packet.dns._all_fields
                    is_response = fields.get('dns.flags.response', 'False') == 'True'
                    transaction_id = fields.get('dns.id', '0x0000')
                    query_name = fields.get('dns.qry.name', '')
                    query_type_code = fields.get('dns.qry.type', '')
                    resp_type_code = fields.get('dns.resp.type', '')
                    resp_name = fields.get('dns.resp.name', '')
                    addresses = []

                    dns_type_map = {
                        '1': 'A',
                        '28': 'AAAA',
                        '65': 'HTTPS',
                        '5': 'CNAME',
                        '6': 'SOA',
                        '2': 'NS'
                    }
                    query_type = dns_type_map.get(query_type_code, f"Type {query_type_code}")
                    resp_type = dns_type_map.get(resp_type_code, f"Type {resp_type_code}")

                    if is_response:
                        if 'dns.a' in fields:
                            if isinstance(fields['dns.a'], list):
                                addresses.extend(fields['dns.a'])
                            else:
                                addresses.append(fields['dns.a'])

                        if 'dns.aaaa' in fields:
                            if isinstance(fields['dns.aaaa'], list):
                                addresses.extend(fields['dns.aaaa'])
                            else:
                                addresses.append(fields['dns.aaaa'])

                        if 'dns.soa.mname' in fields:
                            soa_mname = fields['dns.soa.mname']
                            return f"Standard query response {transaction_id} {resp_type} {resp_name} SOA {soa_mname}"

                        if addresses:
                            return f"Standard query response {transaction_id} {resp_type} {resp_name} " + " ".join(
                                addresses)

                        return f"Standard query response {transaction_id} {resp_type} {resp_name or query_name}"

                    else:
                        return f"Standard query {transaction_id} {query_type} {query_name}"

                except Exception as e:
                    return f"DNS Info unavailable ({e})"

            flags_val = int(packet.tcp.flags, 16)
            flag_str = []
            if flags_val & 0x01: flag_str.append('FIN')
            if flags_val & 0x02: flag_str.append('SYN')
            if flags_val & 0x04: flag_str.append('RST')
            if flags_val & 0x08: flag_str.append('PSH')
            if flags_val & 0x10: flag_str.append('ACK')
            if flags_val & 0x20: flag_str.append('URG')
            if flags_val & 0x40: flag_str.append('ECN-E')
            if flags_val & 0x80: flag_str.append('CWR')
            if flags_val & 0x100: flag_str.append('A-ECN')
            if flags_val & 0x200: flag_str.append('RES')

            return (f"{packet.tcp.srcport} → {packet.tcp.dstport} [{', '.join(flag_str)}] Seq={packet.tcp.seq} "
                    f"Ack={packet.tcp.ack} Win={packet.tcp.window_size_value} Len={packet.tcp.len}")

        elif 'UDP' in packet:
            if 'SSDP' in packet:
                fields = packet.ssdp._all_fields
                method = fields.get('http.request.method', 'UNKNOWN')
                uri = fields.get('http.request.uri', '*')
                version = fields.get('http.request.version', 'HTTP/1.1')
                return f"{method} {uri} {version}"

            elif 'RTCP' in packet:
                def switch(pt):
                    if pt == 200:
                        return "Sender Report"
                    if pt == 201:
                        return "Receiver Report"
                    if pt == 193:
                        return "Negative Acknowledgement"
                    return "Unknown"

                try:
                    info_list = []
                    rtcp_layers = [l for l in packet.layers if l.layer_name == 'rtcp']
                    for l in rtcp_layers:
                        pt = None
                        desc = None
                        try:
                            pt = int(getattr(l, 'pt', '0'))
                        except:
                            pass
                        try:
                            desc = getattr(l, 'rtcp_info', None)
                        except:
                            pass
                        if pt and desc:
                            s = f"{pt} {desc}"
                        elif desc:
                            s = desc
                        elif pt is not None:
                            s = switch(pt)
                        else:
                            s = "RTCP"
                        info_list.append(s)
                    return " | ".join(info_list)

                except Exception as e:
                    return f"RTCP Info unavailable ({e})"

            elif 'NBNS' in packet:
                try:
                    fields = packet.nbns._all_fields
                    name = fields.get('nbns.name', '*')
                    type_code = fields.get('nbns.type', '')
                    is_query = fields.get('nbns.flags.response', 'False') == 'False'
                    type_str = {
                        '32': 'Query',
                        '33': 'NBSTAT',
                    }.get(type_code, f"Type {type_code}")

                    if is_query:
                        return f"Name query {type_str} {name}"
                    else:
                        return f"Name response {type_str} {name}"

                except Exception as e:
                    return f"NBNS Info unavailable ({e})"

            elif 'MDNS' in packet:
                try:
                    fields = packet.mdns._all_fields
                    query_id = fields.get('dns.id', '0x0000')
                    query_type_code = fields.get('dns.qry.type', '')
                    query_name = fields.get('dns.qry.name', '')
                    qu_flag = fields.get('dns.qry.qu', 'False')
                    query_class = fields.get('dns.qry.class', '')
                    qm_qu = '"QM"' if qu_flag == 'False' else '"QU"'

                    query_type_str = {
                        '1': 'A',
                        '12': 'PTR',
                        '28': 'AAAA',
                        '33': 'SRV'
                    }.get(query_type_code, f"Type {query_type_code}")

                    return f"Standard query {query_id} {query_type_str} {query_name}, {qm_qu} question {query_type_str}"

                except Exception as e:
                    return f"MDNS Info unavailable ({e})"

            elif 'QUIC' in packet:
                try:
                    quic_layers = [l for l in packet.layers if l.layer_name == 'quic']
                    results = []

                    for l in quic_layers:
                        fields = l._all_fields
                        header_form = fields.get('quic.header_form', '')
                        packet_type = fields.get('quic.long.packet_type', '')
                        dcid = fields.get('quic.dcid', '').replace(':', '')
                        scid = fields.get('quic.scid', '').replace(':', '')
                        packet_number = fields.get('quic.packet_number', '')
                        frame = fields.get('quic.frame', '')
                        short_hdr = fields.get('quic.short', '')

                        if header_form == '1':
                            type_label = {
                                '0': 'Initial',
                                '1': '0-RTT',
                                '2': 'Handshake',
                                '3': 'Retry'
                            }.get(packet_type, 'Long Header')

                            parts = [type_label]
                            if dcid:
                                parts.append(f"DCID={dcid}")
                            if scid:
                                parts.append(f"SCID={scid}")
                            if packet_number:
                                parts.append(f"PKN: {packet_number}")
                            if frame:
                                parts.append(frame)
                            results.append(", ".join(parts))

                        elif "Protected" in short_hdr or "Short Header" in short_hdr:
                            key_phase = "KP1" if "KP1" in short_hdr else "KP0"
                            label = f"Protected Payload ({key_phase})"
                            if dcid:
                                label += f", DCID={dcid}"
                            results.append(label)

                    return " | ".join(results) if results else "QUIC (undetermined)"

                except Exception as e:
                    return f"QUIC Info unavailable ({e})"

            return f"{packet.udp.srcport} → {packet.udp.dstport} Len={int(len(packet.data.data)/2)}"

        # elif 'ICMP' in packet:
        #     return f"{packet.icmp.type_showname} (Code {packet.icmp.code})"

        elif 'ICMP' in packet:
            try:
                icmp_type = packet.icmp.get_field_value('type')
                icmp_code = packet.icmp.get_field_value('code')

                icmp_types = {
                    '0': "Echo reply",
                    '3': "Destination unreachable",
                    '5': "Redirect",
                    '8': "Echo request",
                    '11': "Time-to-live exceeded",
                    '13': "Timestamp request",
                    '14': "Timestamp reply"
                }

                base = icmp_types.get(icmp_type, f"ICMP type {icmp_type}")
                if icmp_type == '3':
                    code_map = {
                        '0': "Network unreachable",
                        '1': "Host unreachable",
                        '3': "Port unreachable"
                    }
                    extra = code_map.get(icmp_code, f"Code {icmp_code}")
                    return f"{base} ({extra})"

                return base
            except Exception as e:
                return f"ICMP Info unavailable ({e})"

        elif 'ARP' in packet:
            if hasattr(packet.arp, 'opcode'):
                if packet.arp.opcode == '1':
                    return f"Who has {packet.arp.dst_proto_ipv4}? Tell {packet.arp.src_proto_ipv4}"
                elif packet.arp.opcode == '2':
                    return f"{packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"

        return packet.highest_layer

    except Exception as e:
        return "Info unavailable"


def evaluate_condition(packet, cond: str) -> bool:
    cond = cond.strip()

    valid_tags = [
        "TCP", "UDP", "ICMP", "ARP", "HTTP", "RTCP", "TLS",
        "DNS", "IPv6", "QUIC", "MDNS", "NBNS", "SSDP", "DATA"
    ]

    for tag in valid_tags:
        if tag.lower() in cond.lower() and tag.lower() == cond.lower():
            if tag in packet:
                return True

    if "ip.src" in cond and "==" in cond:
        val = cond.split("==")[1].strip()
        return hasattr(packet, "ip") and packet.ip.src == val

    if "ip.dst" in cond and "==" in cond:
        val = cond.split("==")[1].strip()
        return hasattr(packet, "ip") and packet.ip.dst == val

    if ".port" in cond:
        if "==" in cond:
            port = cond.split("==")[1].strip()
            if "tcp.port" in cond:
                return hasattr(packet, "tcp") and (packet.tcp.srcport == port or packet.tcp.dstport == port)
            elif "udp.port" in cond:
                return hasattr(packet, "udp") and (packet.udp.srcport == port or packet.udp.dstport == port)
    elif ".srcport" in cond or ".dstport" in cond:
        for op in ["==", "!=", ">=", "<=", ">", "<"]:
            if op in cond:
                side, val = map(str.strip, cond.split(op))
                val = int(val)
                if "tcp" in side and hasattr(packet, "tcp"):
                    port_attr = "srcport" if "srcport" in side else "dstport"
                    if hasattr(packet.tcp, port_attr):
                        try:
                            port_val = int(getattr(packet.tcp, port_attr))
                            return eval(f"{port_val} {op} {val}")
                        except:
                            return False
                if "udp" in side and hasattr(packet, "udp"):
                    port_attr = "srcport" if "srcport" in side else "dstport"
                    if hasattr(packet.udp, port_attr):
                        try:
                            port_val = int(getattr(packet.udp, port_attr))
                            return eval(f"{port_val} {op} {val}")
                        except:
                            return False

    if "frame.len" in cond:
        for op in ["==", "!=", ">=", "<=", ">", "<"]:
            if op in cond:
                left, right = map(str.strip, cond.split(op))
                try:
                    return eval(f"{int(packet.length)} {op} {int(right)}")
                except:
                    return False

    return False


def apply_display_filter():
    expression = filter_var.get().strip().lower()
    table.delete(*table.get_children())

    for packet in captured_packets:
        try:
            if expression == "":
                show = True
            else:
                expr = expression
                expr = re.sub(r'\s*&&\s*', ' and ', expr)
                expr = re.sub(r'\s*\|\|\s*', ' or ', expr)
                expr = re.sub(r'\s*!\s*', ' not ', expr)

                tokens = re.split(r'(\band\b|\bor\b|\bnot\b|\(|\))', expr)
                tokens = [t.strip() for t in tokens if t.strip()]

                evals = {}
                for t in tokens:
                    if t not in {'and', 'or', 'not', '(', ')'}:
                        evals[t] = evaluate_condition(packet, t)

                safe_expr = " ".join(str(evals[t]) if t in evals else t for t in tokens)
                show = eval(safe_expr)

            if show:
                pkt_index = getattr(packet, "_gui_index", None)
                if pkt_index is not None:
                    values = table_data_map.get(pkt_index)
                    if values:
                        proto_tag = values[4].strip().upper()
                        table.insert("", "end", values=values, tags=(proto_tag,))

        except Exception as e:
            print("[ERROR] Display filter:", e)


def handle_filter_key(event=None):
    apply_display_filter()


# === GUI Setup ===
(root, interface_var, interface_dropdown, start_btn, stop_btn, table, filter_var, filter_entry) = setup_gui(
    start_callback, stop_callback, restart_callback, export_json_callback, upload_pcap_callback,
    view_graphs_callback, show_details_callback)

filter_entry.bind("<Return>", handle_filter_key)
filter_entry_widget = filter_var
populate_interfaces(interface_dropdown, interface_var)
root.after(10, lambda: process_queue(
        packet_queue, table, captured_packets, packet_map, root,
        format_info, start_time_ref, packet_counter_ref, table_data_map
    ))
root.mainloop()
