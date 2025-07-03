def process_queue(packet_queue, table, captured_packets, packet_map, root, format_info,
                  start_time_ref, packet_counter_ref, table_data_map):
    max_packets = 800

    for _ in range(max_packets):
        if packet_queue.empty():
            break
        packet = packet_queue.get()
        try:
            if start_time_ref[0] is None:
                start_time_ref[0] = float(packet.sniff_timestamp)

            packet_counter_ref[0] += 1
            elapsed_time = float(packet.sniff_timestamp) - start_time_ref[0]
            time_str = f"{elapsed_time:.6f}"

            if 'IP' in packet:
                src = getattr(packet.ip, 'src', 'N/A')
                dst = getattr(packet.ip, 'dst', 'N/A')
            else:
                src = getattr(packet.eth, 'src', 'N/A')
                dst = getattr(packet.eth, 'dst', 'N/A')

            transport_proto = packet.transport_layer or "OTHER"
            app_proto = "UDP" if packet.highest_layer == "DATA" else packet.highest_layer
            length = packet.length
            proto_tag = transport_proto.upper() if transport_proto.upper() in [
                "TCP", "UDP", "ICMP", "ARP", "HTTP", "RTCP", "TLS", "DNS", "IPv6", "QUIC",
                "MDNS", "NBNS", "SSDP"] else ""
            info = format_info(packet)

            values = (packet_counter_ref[0], time_str, src, dst, app_proto, length, info)
            table.insert("", "end", values=values, tags=(app_proto,))
            table.yview_moveto(1)

            captured_packets.append(packet)
            packet._gui_index = packet_counter_ref[0]
            packet_map[packet_counter_ref[0]] = packet
            table_data_map[packet_counter_ref[0]] = values

        except Exception as e:
            print(f"[ERROR] Processing packet #{packet_counter_ref[0]}: {e}")

    if packet_queue.qsize() > 0:
        print(f"[INFO] Queue backlog: {packet_queue.qsize()} packets remaining.")

    root.after(10, lambda: process_queue(packet_queue, table, captured_packets, packet_map, root, format_info,
                                         start_time_ref, packet_counter_ref, table_data_map))


def process_packet(packet, table, captured_packets, packet_map, format_info, start_time_ref,
                   packet_counter_ref, table_data_map):
    try:
        if start_time_ref[0] is None:
            start_time_ref[0] = float(packet.sniff_timestamp)

        packet_counter_ref[0] += 1
        elapsed_time = float(packet.sniff_timestamp) - start_time_ref[0]
        time_str = f"{elapsed_time:.6f}"

        if 'IP' in packet:
            src = getattr(packet.ip, 'src', 'N/A')
            dst = getattr(packet.ip, 'dst', 'N/A')
        else:
            src = getattr(packet.eth, 'src', 'N/A')
            dst = getattr(packet.eth, 'dst', 'N/A')

        transport_proto = packet.transport_layer or "OTHER"
        app_proto = "UDP" if packet.highest_layer == "DATA" else packet.highest_layer
        length = packet.length
        proto_tag = transport_proto.upper() if transport_proto.upper() in [
            "TCP", "UDP", "ICMP", "ARP", "HTTP", "RTCP", "TLS", "DNS", "IPv6", "QUIC", "MDNS", "NBNS", "SSDP"] else ""
        info = format_info(packet)

        values = (packet_counter_ref[0], time_str, src, dst, app_proto, length, info)
        table.insert("", "end", values=values, tags=(app_proto,))
        table_data_map[packet_counter_ref[0]] = values
        table.yview_moveto(1)

        captured_packets.append(packet)
        packet._gui_index = packet_counter_ref[0]
        packet_map[packet_counter_ref[0]] = packet

    except Exception as e:
        print(f"[ERROR] Finalizing packet #{packet_counter_ref[0]}: {e}")
