from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import shutil
import os
from uuid import uuid4
import scapy.all as scapy
from parser import parse_pcap, get_packet_layers, hex_dump, get_packet_raw
from fastapi import Query
from scapy.layers.inet import IP, TCP, UDP, ICMP
import re

app = FastAPI()

# CORS settings (for React frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # in prod, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "captures"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Global store (simplu, pt demo; în producție folosește Redis sau DB)
parsed_data = {}
packet_store = {}


# Upload .pcap, parsează și stochează datele.
@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are supported")

    file_id = str(uuid4())
    save_path = os.path.join(UPLOAD_DIR, f"{file_id}.pcap")

    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    packets = scapy.rdpcap(save_path)
    parsed = parse_pcap(save_path)

    parsed_data[file_id] = parsed
    packet_store[file_id] = packets

    print(f"[UPLOAD] Parsed {len(parsed)} packets")

    return {"file_id": file_id, "packet_count": len(parsed)}


# Returnează lista de pachete parse.
@app.get("/packets/{file_id}")
async def get_packets(file_id: str):
    if file_id not in parsed_data:
        raise HTTPException(status_code=404, detail="File ID not found")
    return parsed_data[file_id]


# Detalii structurate (pkt.show()).
@app.get("/packet/{file_id}/{packet_id}")
async def get_packet_details(file_id: str, packet_id: int):
    if file_id not in packet_store:
        raise HTTPException(status_code=404, detail="File ID not found")

    try:
        pkt = packet_store[file_id][packet_id]
        return {"details": get_packet_layers(pkt)}
    except IndexError:
        raise HTTPException(status_code=404, detail="Packet ID out of range")


# Vizualizare hex dump.
@app.get("/packet/{file_id}/{packet_id}/hex")
async def get_packet_hex(file_id: str, packet_id: int):
    if file_id not in packet_store:
        raise HTTPException(status_code=404, detail="File ID not found")

    try:
        raw = get_packet_raw(packet_store[file_id][packet_id])
        return PlainTextResponse(content=hex_dump(raw))
    except IndexError:
        raise HTTPException(status_code=404, detail="Packet ID out of range")


# Exportă fișierul .pcap original.
@app.get("/export/{file_id}")
async def export_pcap(file_id: str):
    filepath = os.path.join(UPLOAD_DIR, f"{file_id}.pcap")
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="Capture not found")
    return FileResponse(filepath, media_type="application/vnd.tcpdump.pcap", filename=f"capture_{file_id}.pcap")


def eval_expression(packet: dict, expression: str) -> bool:
    print(f"[DEBUG] Source: {packet['source']} | Expr: {expression}")
    try:
        packet = {k: str(v) if isinstance(v, (bytes, int, float)) else v for k, v in packet.items()}

        # Înlocuiri
        expr = expression
        expr = expr.replace("ip.src", "packet['source']")
        expr = expr.replace("ip.dst", "packet['destination']")
        expr = expr.replace("protocol", "packet['protocol']")
        expr = expr.replace("length", "packet['length']")
        expr = expr.replace("timestamp", "packet['timestamp']")

        # Găsește expresii de forma: packet['field'] == ceva
        pattern = r"(packet\['\w+'\]\s*==\s*)([^\s\"']+)"
        expr = re.sub(pattern, r'\1"\2"', expr)

        return eval(expr, {"__builtins__": {}}, {"packet": packet})
    except Exception as e:
        print(f"[Eval error] {expression} => {e}")
        return False


# Filtrare pachetelor
@app.get("/packets/{file_id}/filter")
async def filter_packets(file_id: str, filter: str = Query("")):
    if file_id not in parsed_data:
        raise HTTPException(status_code=404, detail="File ID not found")

    if not filter.strip():
        return parsed_data[file_id]

    filtered = [pkt for pkt in parsed_data[file_id] if eval_expression(pkt, filter)]
    return filtered
