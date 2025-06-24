import React from 'react';
import { Button } from '@mui/material';

const UploadForm = ({ onUpload }) => {
    const handleFileChange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("http://localhost:8000/upload", {
            method: "POST",
            body: formData,
        });

        const data = await response.json();
        onUpload(data.file_id);
    };

    return (
        <div>
            <input type="file" accept=".pcap" onChange={handleFileChange} />
            <Button variant="contained" sx={{ mt: 1 }}>Upload</Button>
        </div>
    );
};

export default UploadForm;
