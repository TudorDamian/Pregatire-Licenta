import React, { useState } from "react";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Container from "@mui/material/Container";
import Typography from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import Box from "@mui/material/Box";
import Autocomplete from "@mui/material/Autocomplete";

const FILTER_FIELDS = [
    "ip.src",
    "ip.dst",
    "protocol",
    "length",
    "timestamp",
    'ip.src == "192.168.1.1"',
    'protocol == "TCP"',
    "length > 60",
];

function ResponsiveAppBar({ onFilterChange }) {
    const [filter, setFilter] = useState("");

    const handleApply = () => {
        onFilterChange(filter);
    };

    const handleClear = () => {
        setFilter("");
        onFilterChange("");
    };

    return (
        <AppBar position="static" sx={{ backgroundColor: "#7F7F7F", fontFamily: '"Arial", sans-serif' }} elevation={0}>
            <Container sx={{ display: "flex-start", py: 2 }}>
                <Toolbar sx={{ display: "flex", flexDirection: "column", width: "100%" }}>
                    <Typography variant="h6" sx={{ color: "#fff", mb: 1 }}>
                        Packet Analyzer
                    </Typography>

                    <Box sx={{ display: "flex", gap: 1, width: "100%" }}>
                        <Autocomplete
                            fullWidth={true}
                            freeSolo
                            options={FILTER_FIELDS}
                            inputValue={filter}
                            onInputChange={(event, newInputValue) => setFilter(newInputValue)}
                            renderInput={(params) => (
                                <TextField
                                    {...params}
                                    fullWidth
                                    size="small"
                                    placeholder="Start typing a Display Filter"
                                    variant="outlined"
                                    sx={{ backgroundColor: "#fff", borderRadius: 1 }}
                                />
                            )}
                        />
                        <Button variant="contained" onClick={handleApply}>Apply</Button>
                        <Button variant="outlined" onClick={handleClear}>Clear</Button>
                    </Box>
                </Toolbar>
            </Container>
        </AppBar>
    );
}

export default ResponsiveAppBar;
