// import React, { useState } from "react";
// import UploadForm from "./components/UploadForm";
// import HeaderBar from "./components/HeaderBar";
// import FilterBar from "./components/FilterBar";
// import PacketTableCloud from "./components/PacketTableCloud";
// import PacketDetailsTabs from "./components/PacketDetailsTabs";
//
// export default function AppCloudshark() {
//     const [fileId, setFileId] = useState(null);
//     const [packets, setPackets] = useState([]);
//     const [selectedPacket, setSelectedPacket] = useState(null);
//     const [filterText, setFilterText] = useState("");
//
//     const filteredPackets = packets.filter((pkt) => {
//         if (!filterText) return true;
//         return (
//             pkt.source.includes(filterText) ||
//             pkt.destination.includes(filterText) ||
//             pkt.protocol.toLowerCase().includes(filterText.toLowerCase()) ||
//             pkt.info.toLowerCase().includes(filterText.toLowerCase())
//         );
//     });
//
//     return (
//         <div className="h-screen flex flex-col bg-gray-100 text-sm font-mono">
//             <HeaderBar
//                 fileId={fileId}
//                 packetCount={packets.length}
//                 setFileId={setFileId}
//                 setPackets={setPackets}
//             />
//             <FilterBar value={filterText} onChange={setFilterText} />
//
//             <div className="flex-grow grid grid-rows-[1fr_auto] overflow-hidden">
//                 <PacketTableCloud
//                     packets={filteredPackets}
//                     onSelect={setSelectedPacket}
//                     selectedId={selectedPacket?.id}
//                 />
//                 {selectedPacket && (
//                     <PacketDetailsTabs
//                         fileId={fileId}
//                         packetId={selectedPacket.id}
//                     />
//                 )}
//             </div>
//         </div>
//     );
// }


import React from "react";
import {
    Card,
    CardContent,
    Typography,
    TextField,
    Button,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper
} from "@mui/material";

const packets = [
    { no: 1, time: "0.000000", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 60, info: "37019 → 179 [SYN] Seq=0 Win=16384 Len=0 MSS=1460" },
    { no: 2, time: "0.000025", source: "192.168.12.2", destination: "192.168.12.1", protocol: "TCP", length: 58, info: "179 → 37019 [SYN, ACK] Seq=0 Ack=1 Win=16384 Len=0 MSS=1460" },
    { no: 3, time: "0.000195", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 54, info: "37019 → 179 [ACK] Seq=1 Ack=1 Win=16384 Len=0" },
    { no: 4, time: "0.001076", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 111, info: "OPEN Message" },
    { no: 5, time: "0.001431", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 114, info: "OPEN Message" },
    { no: 6, time: "0.001756", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 54, info: "37019 → 179 [ACK] Seq=1 Ack=58 Win=16327 Len=0" },
    { no: 7, time: "0.038537", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    { no: 8, time: "0.041097", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 73, info: "37019 → 179 [ACK] Seq=58 Ack=77 Win=16308 Len=0" },
    { no: 9, time: "0.042617", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    { no: 10, time: "0.049259", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    { no: 11, time: "0.054598", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 131, info: "UPDATE Message, UPDATE Message" },
    { no: 12, time: "0.057318", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 131, info: "UPDATE Message, UPDATE Message" },
    { no: 13, time: "0.060242", source: "192.168.12.2", destination: "192.168.12.1", protocol: "TCP", length: 60, info: "37019 → 179 [ACK] Seq=173 Ack=173 Win=16212 Len=0" },
];

export default function App() {
    return (
        <div style={{ padding: 24 }}>
            <Typography variant="h5" gutterBottom>
                bgp-ebgp-neighbor-adjacency.pcap
            </Typography>
            <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                <TextField label="Start typing a Display Filter" variant="outlined" fullWidth />
                <Button variant="contained">Apply</Button>
                <Button variant="outlined">Clear</Button>
            </div>

            <Card>
                <CardContent>
                    <TableContainer component={Paper}>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>No.</TableCell>
                                    <TableCell>Time</TableCell>
                                    <TableCell>Source</TableCell>
                                    <TableCell>Destination</TableCell>
                                    <TableCell>Protocol</TableCell>
                                    <TableCell>Length</TableCell>
                                    <TableCell>Info</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {packets.map((packet) => (
                                    <TableRow key={packet.no}>
                                        <TableCell>{packet.no}</TableCell>
                                        <TableCell>{packet.time}</TableCell>
                                        <TableCell>{packet.source}</TableCell>
                                        <TableCell>{packet.destination}</TableCell>
                                        <TableCell>{packet.protocol}</TableCell>
                                        <TableCell>{packet.length}</TableCell>
                                        <TableCell>{packet.info}</TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </CardContent>
            </Card>
        </div>
    );
}