// import { Box } from '@mui/material';
//
// const HexView = () => {
//     // const hexData = `
//     //     0000   45 00 00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 00 01
//     //     0010   c0 a8 00 c7 00 50 00 18 00 00 00 00 00 00 00 00
//     //     0020   50 02 20 00 91 7c 00 00 48 65 6c 6c 6f 2c 20 77
//     //     0030   6f 72 6c 64 21
//     // `;
//
//     return (
//         <Box>
//             <Box sx={{ fontFamily: 'monospace', maxHeight: 200, overflowY: 'auto' }}>
//                 <pre>{hexData}</pre>
//             </Box>
//         </Box>
//     );
// };

const HexView = ({ hex }) => (
    <pre style={{ fontFamily: 'monospace', fontSize: '12px', whiteSpace: 'pre-wrap' }}>{hex || "Select a packet..."}</pre>
);

export default HexView;