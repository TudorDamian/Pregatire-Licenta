import threading
import asyncio
import os
from datetime import datetime
import pyshark
import psutil
import tkinter as tk

captured_packets = []
packet_queue = None
packet_counter = 0
sniffing = False
start_time = None
last_pcap_path = None
EXPORT_PCAP_DIR = "./capture/captures_exported_pcapng"
os.makedirs(EXPORT_PCAP_DIR, exist_ok=True)


def start_capture(interface, queue_ref, start_btn, stop_btn):
    global sniffing, packet_counter, start_time, last_pcap_path, packet_queue
    packet_queue = queue_ref
    asyncio.set_event_loop(asyncio.new_event_loop())
    sniffing = True
    packet_counter = 0
    start_time = None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    last_pcap_path = os.path.join(EXPORT_PCAP_DIR, f"live_capture_{timestamp}.pcapng")
    capture = pyshark.LiveCapture(interface=interface, output_file=last_pcap_path)

    start_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    try:
        for packet in capture.sniff_continuously():
            if not sniffing:
                break
            packet_queue.put(packet)
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture.close()


def populate_interfaces(interface_dropdown, interface_var):
    interfaces = list_interfaces()
    interface_dropdown['values'] = interfaces
    if interfaces:
        interface_var.set(interfaces[0])


def get_interface_names():
    interfaces = psutil.net_if_addrs()
    return {iface: iface for iface in interfaces}


def list_interfaces():
    interface_map = get_interface_names()
    return list(interface_map.keys())


def start_sniffing(interface_var, clear_table, captured_packets_ref, queue_ref, start_btn, stop_btn):
    iface = interface_var.get()
    if iface:
        clear_table()
        captured_packets_ref.clear()
        threading.Thread(target=start_capture, args=(iface, queue_ref, start_btn, stop_btn), daemon=True).start()
        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)


def stop_sniffing(process_packet, stop_btn, start_btn):
    global sniffing
    sniffing = False
    start_btn.config(state=tk.NORMAL)
    stop_btn.config(state=tk.DISABLED)

    while not packet_queue.empty():
        process_packet(packet_queue.get())


def restart_capture(start_sniff, stop_sniff):
    stop_sniff()
    start_sniff()
