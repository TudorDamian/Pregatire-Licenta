import json
import os
from datetime import datetime

EXPORT_JSON_DIR = "./capture/captures_exported_json"
os.makedirs(EXPORT_JSON_DIR, exist_ok=True)


def packet_to_dict(pkt):
    pkt_dict = {
        "@timestamp": pkt.sniff_time.isoformat() + "Z",
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


def export_all_packets_json(captured_packets):
    if not captured_packets:
        print("[WARN] No packets to export as JSON.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{EXPORT_JSON_DIR}/capture_json_{timestamp}.json"

    try:
        with open(filename, "w") as f:
            for pkt in captured_packets:
                pkt_dict = packet_to_dict(pkt)
                f.write(json.dumps(pkt_dict) + "\n")
        print(f"Exported JSON Lines to: {filename}")
    except Exception as e:
        print(f"Failed to export JSON: {e}")


def view_graphs(captured_packets):
    if not captured_packets:
        print("[WARN] No packets to export as JSON.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_elk = f"./elk/captures/pcap_packets_{timestamp}.json"

    try:
        with open(filename_elk, "w") as f:
            for pkt in captured_packets:
                pkt_dict = packet_to_dict(pkt)
                f.write(json.dumps(pkt_dict) + "\n")
        print(f"Exported JSON Lines to: {filename_elk}")
    except Exception as e:
        print(f"Failed to export JSON: {e}")
