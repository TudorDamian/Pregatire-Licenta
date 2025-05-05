import React from "react";

export default function PacketTable({ packets, onSelect }) {
    return (
        <div className="overflow-auto border rounded bg-white shadow">
            <table className="min-w-full text-sm">
                <thead className="bg-gray-200">
                <tr>
                    <th className="px-2 py-1">ID</th>
                    <th className="px-2 py-1">Time</th>
                    <th className="px-2 py-1">Source</th>
                    <th className="px-2 py-1">Destination</th>
                    <th className="px-2 py-1">Proto</th>
                    <th className="px-2 py-1">Len</th>
                    <th className="px-2 py-1">Info</th>
                </tr>
                </thead>
                <tbody>
                {packets.map((pkt) => (
                    <tr
                        key={pkt.id}
                        className="cursor-pointer hover:bg-blue-50"
                        onClick={() => onSelect(pkt)}
                    >
                        <td className="px-2 py-1 text-center">{pkt.id}</td>
                        <td className="px-2 py-1 text-center">{pkt.timestamp.toFixed(6)}</td>
                        <td className="px-2 py-1">{pkt.source}</td>
                        <td className="px-2 py-1">{pkt.destination}</td>
                        <td className="px-2 py-1 text-center">{pkt.protocol}</td>
                        <td className="px-2 py-1 text-center">{pkt.length}</td>
                        <td className="px-2 py-1">{pkt.info}</td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
}
