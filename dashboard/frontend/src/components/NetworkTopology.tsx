import React, { useEffect, useRef } from 'react';
import { Box, Typography } from '@mui/material';

interface NetworkTopologyProps {
    alerts: any[];
}

const NetworkTopology: React.FC<NetworkTopologyProps> = ({ alerts }) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        canvas.width = canvas.offsetWidth;
        canvas.height = 300;

        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;

        // Extract unique sources and destinations
        const sources = Array.from(new Set(alerts.map(a => a.src_ip))).slice(0, 12);
        const destinations = Array.from(new Set(alerts.map(a => a.dst_ip))).slice(0, 8);

        const nodes = [
            { x: centerX, y: centerY, label: 'GATEWAY', size: 15, color: '#00ffff', type: 'center' },
            ...sources.map((ip, i) => {
                const angle = (i / sources.length) * Math.PI * 2;
                return {
                    x: centerX + Math.cos(angle) * 100,
                    y: centerY + Math.sin(angle) * 100,
                    label: ip?.slice(-7) || 'N/A',
                    size: 8,
                    color: '#ff0080',
                    type: 'source'
                };
            }),
            ...destinations.map((ip, i) => {
                const angle = (i / destinations.length) * Math.PI * 2 + Math.PI;
                return {
                    x: centerX + Math.cos(angle) * 60,
                    y: centerY + Math.sin(angle) * 60,
                    label: ip?.slice(-7) || 'N/A',
                    size: 6,
                    color: '#00ff41',
                    type: 'dest'
                };
            }),
        ];

        let frame = 0;

        const animate = () => {
            frame++;
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw connections with animated data flow
            nodes.forEach((node, i) => {
                if (i === 0) return; // Skip center

                // Line to center
                ctx.strokeStyle = node.type === 'source' ? 'rgba(255, 0, 128, 0.4)' : 'rgba(0, 255, 65, 0.4)';
                ctx.lineWidth = 2;
                ctx.setLineDash([5, 5]);
                ctx.lineDashOffset = -frame * 0.5;

                ctx.beginPath();
                ctx.moveTo(node.x, node.y);
                ctx.lineTo(centerX, centerY);
                ctx.stroke();
                ctx.setLineDash([]);

                // Animated data packets
                const progress = (frame % 60) / 60;
                const packetX = node.x + (centerX - node.x) * progress;
                const packetY = node.y + (centerY - node.y) * progress;

                const gradient = ctx.createRadialGradient(packetX, packetY, 0, packetX, packetY, 4);
                gradient.addColorStop(0, '#ffffff');
                gradient.addColorStop(1, node.color);

                ctx.fillStyle = gradient;
                ctx.beginPath();
                ctx.arc(packetX, packetY, 3, 0, Math.PI * 2);
                ctx.fill();
            });

            // Draw nodes
            nodes.forEach((node) => {
                // Outer glow
                const glowSize = node.size + Math.sin(frame * 0.05) * 2;
                const gradient = ctx.createRadialGradient(
                    node.x, node.y, 0,
                    node.x, node.y, glowSize
                );
                gradient.addColorStop(0, node.color);
                gradient.addColorStop(1, 'transparent');

                ctx.fillStyle = gradient;
                ctx.beginPath();
                ctx.arc(node.x, node.y, glowSize, 0, Math.PI * 2);
                ctx.fill();

                // Core
                ctx.fillStyle = node.color;
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
                ctx.fill();

                // Border
                ctx.strokeStyle = '#ffffff';
                ctx.lineWidth = 2;
                ctx.stroke();

                // Label
                ctx.fillStyle = '#00ff41';
                ctx.font = '9px "Fira Code", monospace';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + node.size + 12);
            });

            requestAnimationFrame(animate);
        };

        animate();

        const handleResize = () => {
            canvas.width = canvas.offsetWidth;
            canvas.height = 300;
        };

        window.addEventListener('resize', handleResize);

        return () => {
            window.removeEventListener('resize', handleResize);
        };
    }, [alerts]);

    return (
        <Box sx={{ p: 2 }}>
            <Typography 
                variant="h6" 
                sx={{ 
                    mb: 2, 
                    color: '#00ff41', 
                    fontFamily: '"Orbitron", monospace',
                    textShadow: '0 0 10px #00ff41'
                }}
            >
                <span style={{ marginRight: '10px' }}>🔗</span>
                NETWORK TOPOLOGY
            </Typography>
            <canvas
                ref={canvasRef}
                style={{
                    width: '100%',
                    height: '300px',
                    background: 'rgba(0, 0, 0, 0.5)',
                    borderRadius: '4px',
                }}
            />
            <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-around', fontSize: '0.8rem' }}>
                <span style={{ color: '#00ffff' }}>◉ GATEWAY</span>
                <span style={{ color: '#ff0080' }}>● SOURCES</span>
                <span style={{ color: '#00ff41' }}>● DESTINATIONS</span>
            </Box>
        </Box>
    );
};

export default NetworkTopology;
