import os
import json
from datetime import datetime

# Locația unde Logstash citește fișierele
output_dir = "./elk/captures"
os.makedirs(output_dir, exist_ok=True)

# Numele fișierului JSON (folosește timestamp pentru unicitate)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(output_dir, f"packets_{timestamp}.json")

# Pachete de test
packets = [
    {
        "id": 1,
        "timestamp": 0.001,
        "source": "192.168.1.2",
        "destination": "192.168.1.1",
        "protocol": "TCP",
        "length": 60,
        "info": "SYN"
    },
    {
        "id": 2,
        "timestamp": 0.002,
        "source": "192.168.1.1",
        "destination": "192.168.1.2",
        "protocol": "TCP",
        "length": 52,
        "info": "SYN, ACK"
    },
    {
        "id": 3,
        "timestamp": 0.003,
        "source": "192.168.1.2",
        "destination": "192.168.1.1",
        "protocol": "TCP",
        "length": 48,
        "info": "ACK"
    }
]

# Scrie în format json_lines
with open(output_file, "w") as f:
    for pkt in packets:
        f.write(json.dumps(pkt) + "\n")

print(f"[✔] Fișier generat: {output_file}")
