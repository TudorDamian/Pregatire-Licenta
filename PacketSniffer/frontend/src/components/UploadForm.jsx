import React, { useRef } from "react";
import axios from "axios";

export default function UploadForm({ setFileId, setPackets }) {
    const fileInputRef = useRef();

    const handleUpload = async () => {
        const file = fileInputRef.current.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await axios.post("http://localhost:8000/upload", formData, {
                headers: { "Content-Type": "multipart/form-data" },
            });

            setFileId(res.data.file_id);

            const packetRes = await axios.get(`http://localhost:8000/packets/${res.data.file_id}`);
            setPackets(packetRes.data);
        } catch (err) {
            console.error("Upload failed:", err);
            alert("Failed to upload and parse PCAP file.");
        }
    };

    return (
        <div className="flex items-center gap-4">
            <input type="file" accept=".pcap" ref={fileInputRef} className="border p-2" />
            <button
                onClick={handleUpload}
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            >
                Upload & Analyze
            </button>
        </div>
    );
}