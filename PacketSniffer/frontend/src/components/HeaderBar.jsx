import React from "react";
import UploadForm from "./UploadForm";

export default function HeaderBar({ fileId, packetCount, setFileId, setPackets }) {
    return (
        <div className="bg-white border-b px-4 py-2 flex items-center justify-between shadow-sm">
            <div>
                <h1 className="text-lg font-semibold">CloudShark Clone</h1>
                {fileId && (
                    <span className="text-xs text-gray-500">
            File ID: {fileId} | Packets: {packetCount}
          </span>
                )}
            </div>

            <div className="flex gap-4 items-center">
                <UploadForm setFileId={setFileId} setPackets={setPackets} />
                {fileId && (
                    <a
                        href={`http://localhost:8000/export/${fileId}`}
                        className="text-sm text-blue-600 hover:underline"
                        download
                    >
                        Export .pcap
                    </a>
                )}
            </div>
        </div>
    );
}
