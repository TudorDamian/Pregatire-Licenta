import React, { useEffect, useState } from 'react';
import ResponsiveAppBar from '../components/ResponsiveAppBar';
import PacketList from '../components/PacketList';
import PrettyPacketView from '../components/PrettyPacketView';
import HexView from '../components/HexView';
import UploadForm from '../components/UploadForm';
import {
    Container,
    Content,
    UpperBox,
    LowerBox,
    LeftSection,
    RightSection
} from './DashboardPage.styles';

const DashboardPage = () => {
    const [fileId, setFileId] = useState(null);
    const [packets, setPackets] = useState([]);
    const [selectedPacketId, setSelectedPacketId] = useState(null);
    const [packetDetails, setPacketDetails] = useState("");
    const [packetHex, setPacketHex] = useState("");

    const [filterText, setFilterText] = useState("");

    useEffect(() => {
        if (!fileId) return;
        fetch(`http://localhost:8000/packets/${fileId}`)
            .then(res => res.json())
            .then(data => setPackets(data));
    }, [fileId]);

    useEffect(() => {
        if (fileId && selectedPacketId !== null) {
            fetch(`http://localhost:8000/packet/${fileId}/${selectedPacketId}`)
                .then(res => res.json())
                .then(data => setPacketDetails(data.details));

            fetch(`http://localhost:8000/packet/${fileId}/${selectedPacketId}/hex`)
                .then(res => res.text())
                .then(setPacketHex);
        }
    }, [fileId, selectedPacketId]);

    const handleFilterChange = (text) => {
        setFilterText(text);

        if (fileId && text.trim()) {
            fetch(`http://localhost:8000/packets/${fileId}/filter?filter=${encodeURIComponent(text)}`)
                .then(res => res.json())
                .then(setPackets);
        } else if (fileId) {
            fetch(`http://localhost:8000/packets/${fileId}`)
                .then(res => res.json())
                .then(setPackets);
        }
    };

    return (
        <Container>
            {/*Toolbar-ul*/}
            <ResponsiveAppBar onFilterChange={handleFilterChange} />
            <Content>
                <UploadForm onUpload={setFileId} />
                {fileId && (
                    <>
                        <UpperBox>
                            <PacketList
                                packets={packets}
                                onSelect={(id) => setSelectedPacketId(id)}
                            />
                        </UpperBox>
                        <LowerBox>
                            <LeftSection>
                                <PrettyPacketView details={packetDetails} />
                            </LeftSection>
                            <RightSection>
                                <HexView hex={packetHex} />
                            </RightSection>
                        </LowerBox>
                    </>
                )}
            </Content>
        </Container>
    );
};

export default DashboardPage;