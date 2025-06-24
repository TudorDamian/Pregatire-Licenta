import {
    Paper,
    Table, TableBody, TableCell, TableContainer,
    TableHead, TableRow, TableSortLabel
} from '@mui/material';
import React, { useState } from 'react';

const PacketList = ({ packets, onSelect }) => {
    const [orderBy, setOrderBy] = useState('no');
    const [order, setOrder] = useState('asc');

    // const rows = [
    //     { no: 1, time: "0.000000", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 60, info: "37019 → 179 [SYN] Seq=0 Win=16384 Len=0 MSS=1460" },
    //     { no: 2, time: "0.000025", source: "192.168.12.2", destination: "192.168.12.1", protocol: "TCP", length: 58, info: "179 → 37019 [SYN, ACK] Seq=0 Ack=1 Win=16384 Len=0 MSS=1460" },
    //     { no: 3, time: "0.000195", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 54, info: "37019 → 179 [ACK] Seq=1 Ack=1 Win=16384 Len=0" },
    //     { no: 4, time: "0.001076", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 111, info: "OPEN Message" },
    //     { no: 5, time: "0.001431", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 114, info: "OPEN Message" },
    //     { no: 6, time: "0.001756", source: "192.168.12.1", destination: "192.168.12.2", protocol: "TCP", length: 54, info: "37019 → 179 [ACK] Seq=1 Ack=58 Win=16327 Len=0" },
    //     { no: 7, time: "0.038537", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    //     { no: 8, time: "0.041097", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 73, info: "37019 → 179 [ACK] Seq=58 Ack=77 Win=16308 Len=0" },
    //     { no: 9, time: "0.042617", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    //     { no: 10, time: "0.049259", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 73, info: "KEEPALIVE Message" },
    //     { no: 11, time: "0.054598", source: "192.168.12.2", destination: "192.168.12.1", protocol: "BGP", length: 131, info: "UPDATE Message, UPDATE Message" },
    //     { no: 12, time: "0.057318", source: "192.168.12.1", destination: "192.168.12.2", protocol: "BGP", length: 131, info: "UPDATE Message, UPDATE Message" },
    //     { no: 13, time: "0.060242", source: "192.168.12.2", destination: "192.168.12.1", protocol: "TCP", length: 60, info: "37019 → 179 [ACK] Seq=173 Ack=173 Win=16212 Len=0" },
    // ];

    const handleSort = (property) => {
        const isAsc = orderBy === property && order === 'asc';
        setOrder(isAsc ? 'desc' : 'asc');
        setOrderBy(property);
    };

    const sortedRows = [...packets].sort((a, b) => {
        if (a[orderBy] < b[orderBy]) return order === 'asc' ? -1 : 1;
        if (a[orderBy] > b[orderBy]) return order === 'asc' ? 1 : -1;
        return 0;
    });

    return (
        <Paper sx={{ width: '100%', overflow: 'hidden' }}>
            <TableContainer sx={{maxHeight: 400}}>
                <Table size="small" stickyHeader>
                    <TableHead>
                        <TableRow>
                            {['id', 'timestamp', 'source', 'destination', 'protocol', 'length', 'info'].map((column) => (
                                <TableCell key={column}>
                                    <TableSortLabel
                                        active={orderBy === column}
                                        direction={orderBy === column ? order : 'asc'}
                                        onClick={() => handleSort(column)}
                                    >
                                        {column.charAt(0).toUpperCase() + column.slice(1)}
                                    </TableSortLabel>
                                </TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {sortedRows.map((row) => (
                            <TableRow key={row.id} onClick={() => onSelect(row.id)} hover>
                                <TableCell>{row.id}</TableCell>
                                <TableCell>{row.timestamp.toFixed(6)}</TableCell>
                                <TableCell>{row.source}</TableCell>
                                <TableCell>{row.destination}</TableCell>
                                <TableCell>{row.protocol}</TableCell>
                                <TableCell>{row.length}</TableCell>
                                <TableCell>{row.info}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        </Paper>
    );
};

export default PacketList;
