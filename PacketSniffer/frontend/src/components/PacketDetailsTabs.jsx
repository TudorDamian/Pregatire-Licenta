import React, { useEffect, useState } from "react";
import axios from "axios";

export default function PacketDetailsTabs({ fileId, packetId }) {
    const [tab, setTab] = useState("details");
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
            } catch (e) {
                console.error("Failed to load packet details", e);
            }
        }
        fetchData();
    }, [fileId, packetId]);

    return (
        <div className="h-[300px] bg-white border-t p-2">
            <div className="flex space-x-4 border-b mb-2">
                <button
                    onClick={() => setTab("details")}
                    className={`px-4 py-1 ${tab === "details" ? "border-b-2 border-blue-600 text-blue-600" : "text-gray-600"}`}
                >
                    Packet Info
                </button>
                <button
                    onClick={() => setTab("hex")}
                    className={`px-4 py-1 ${tab === "hex" ? "border-b-2 border-blue-600 text-blue-600" : "text-gray-600"}`}
                >
                    Hex View
                </button>
            </div>
            <div className="overflow-auto h-full">
                {tab === "details" && (
                    <pre className="text-xs whitespace-pre-wrap font-mono bg-gray-50 p-2">{details}</pre>
                )}
                {tab === "hex" && (
                    <pre className="text-xs whitespace-pre font-mono bg-gray-50 p-2">{hex}</pre>
                )}
            </div>
        </div>
    );
}
