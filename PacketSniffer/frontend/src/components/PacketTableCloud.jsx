import React from "react";

const protocolColors = {
    TCP: "bg-red-100",
    UDP: "bg-blue-100",
    ICMP: "bg-yellow-100",
    ARP: "bg-pink-100",
    IPv6: "bg-gray-200",
    Other: "bg-white",
};

export default function PacketTableCloud({ packets, onSelect, selectedId }) {
    return (
        <div className="overflow-auto border-t border-b bg-white font-mono text-xs">
            <table className="min-w-full">
                <thead className="bg-gray-200">
                <tr>
                    <th className="px-2 py-1 text-left">No.</th>
                    <th className="px-2 py-1 text-left">Time</th>
                    <th className="px-2 py-1 text-left">Source</th>
                    <th className="px-2 py-1 text-left">Destination</th>
                    <th className="px-2 py-1 text-left">Protocol</th>
                    <th className="px-2 py-1 text-left">Length</th>
                    <th className="px-2 py-1 text-left">Info</th>
                </tr>
                </thead>
                <tbody>
                {packets.map((pkt) => (
                    <tr
                        key={pkt.id}
                        onClick={() => onSelect(pkt)}
                        className={`${protocolColors[pkt.protocol] || ""} hover:bg-blue-50 cursor-pointer ${
                            selectedId === pkt.id ? "ring-2 ring-blue-400" : ""
                        }`}
                    >
                        <td className="px-2 py-1">{pkt.id}</td>
                        <td className="px-2 py-1">{pkt.timestamp.toFixed(6)}</td>
                        <td className="px-2 py-1">{pkt.source}</td>
                        <td className="px-2 py-1">{pkt.destination}</td>
                        <td className="px-2 py-1">{pkt.protocol}</td>
                        <td className="px-2 py-1">{pkt.length}</td>
                        <td className="px-2 py-1 whitespace-nowrap overflow-hidden truncate max-w-[250px]">
                            {pkt.info}
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
}
