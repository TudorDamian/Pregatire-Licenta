import React, { useEffect, useState } from "react";
import axios from "axios";

export default function PacketDetails({ fileId, packetId }) {
    const [details, setDetails] = useState("");
    const [hex, setHex] = useState("");

    useEffect(() => {
        async function fetchData() {
            try {
                const detailRes = await axios.get(`http://localhost:8000/packet/${fileId}/${packetId}`);
                const hexRes = await axios.get(`http://localhost:8000/packet/${fileId}/${packetId}/hex`, {
                    headers: { Accept: "text/plain" },
                });

                setDetails(detailRes.data.details);
                setHex(hexRes.data);
            } catch (err) {
                console.error("Failed to fetch packet details:", err);
            }
        }
        fetchData();
    }, [fileId, packetId]);

    return (
        <div className="bg-white p-4 rounded shadow overflow-auto">
            <h2 className="font-semibold text-lg mb-2">Packet #{packetId} Details</h2>
            <div className="mb-4">
                <h3 className="font-medium">Layer Info</h3>
                <pre className="bg-gray-100 p-2 overflow-x-auto text-sm whitespace-pre-wrap">{details}</pre>
            </div>
            <div>
                <h3 className="font-medium">Hex View</h3>
                <pre className="bg-gray-100 p-2 overflow-x-auto text-sm whitespace-pre">{hex}</pre>
            </div>
        </div>
    );
}
