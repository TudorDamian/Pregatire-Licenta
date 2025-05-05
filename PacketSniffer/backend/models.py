from pydantic import BaseModel
from typing import Literal


class ParsedPacket(BaseModel):
    id: int
    timestamp: float
    source: str
    destination: str
    protocol: Literal["TCP", "UDP", "ICMP", "ARP", "IPv6", "Other"]
    length: int
    info: str


class UploadResponse(BaseModel):
    file_id: str
    packet_count: int


class PacketDetails(BaseModel):
    details: str  # conținutul `pkt.show(dump=True)`
