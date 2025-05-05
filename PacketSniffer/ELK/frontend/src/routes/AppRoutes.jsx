import React from "react";
import { Routes, Route } from "react-router-dom";
import Dashboard from "../pages/dashboardPage/DashboardPage";

const AppRoutes = () => {
    return (
        <Routes>
            {/* Public */}
            <Route path="/" element={<Dashboard />} />
        </Routes>
    );
};

export default AppRoutes;