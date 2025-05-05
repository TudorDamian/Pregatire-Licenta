import React from "react";
import { Search } from "lucide-react";

export default function FilterBar({ value, onChange }) {
    return (
        <div className="bg-gray-50 px-4 py-2 border-b flex items-center gap-2">
            <Search className="h-4 w-4 text-gray-500" />
            <input
                type="text"
                placeholder="Type a filter (e.g. ip.src == 192.168.1.1)"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                className="flex-grow bg-white border border-gray-300 rounded px-3 py-1 text-sm focus:outline-none"
            />
        </div>
    );
}
