// import { Box, Typography } from '@mui/material';
//
// const PrettyPacketView = () => {
//     return (
//         <Box>
//             <Typography variant="body2">Source IP: 192.168.0.1</Typography>
//             <Typography variant="body2">Destination IP: 192.168.0.2</Typography>
//             <Typography variant="body2">Protocol: TCP</Typography>
//             <Typography variant="body2">Payload: GET /index.html</Typography>
//         </Box>
//     );
// };

const PrettyPacketView = ({ details }) => (
    <pre style={{ fontSize: '13px', whiteSpace: 'pre-wrap' }}>{details || "Select a packet..."}</pre>
);

export default PrettyPacketView;