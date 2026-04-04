import React, { useEffect, useRef } from 'react';
import { Box, Typography } from '@mui/material';

interface ThreatMapProps {
    alerts: any[];
}

const ThreatMap: React.FC<ThreatMapProps> = ({ alerts }) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        canvas.width = canvas.offsetWidth;
        canvas.height = 300;

        // Simplified world map outline
        const drawWorldMap = () => {
            ctx.strokeStyle = 'rgba(0, 255, 65, 0.3)';
            ctx.lineWidth = 1;

            // Draw simplified continents (artistic representation)
            ctx.beginPath();
            // North America
            ctx.moveTo(100, 80);
            ctx.lineTo(120, 100);
            ctx.lineTo(140, 90);
            ctx.lineTo(160, 120);
            ctx.lineTo(100, 80);

            // Europe
            ctx.moveTo(250, 70);
            ctx.lineTo(270, 80);
            ctx.lineTo(280, 90);
            ctx.lineTo(260, 100);

            // Asia
            ctx.moveTo(320, 80);
            ctx.lineTo(380, 70);
            ctx.lineTo(420, 90);
            ctx.lineTo(400, 120);
            ctx.lineTo(360, 110);
            ctx.lineTo(320, 80);

            // Africa
            ctx.moveTo(250, 120);
            ctx.lineTo(270, 150);
            ctx.lineTo(280, 180);
            ctx.lineTo(260, 200);
            ctx.lineTo(240, 180);

            // South America
            ctx.moveTo(140, 160);
            ctx.lineTo(150, 190);
            ctx.lineTo(145, 220);
            ctx.lineTo(130, 210);

            // Australia
            ctx.moveTo(400, 190);
            ctx.lineTo(430, 200);
            ctx.lineTo(420, 220);
            ctx.lineTo(390, 210);

            ctx.stroke();
        };

        // Animate threat markers
        const threats = alerts.slice(0, 20).map((alert, i) => ({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            severity: alert.severity,
            pulse: Math.random() * Math.PI * 2,
        }));

        const animate = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Grid background
            ctx.strokeStyle = 'rgba(0, 255, 65, 0.05)';
            ctx.lineWidth = 0.5;
            for (let x = 0; x < canvas.width; x += 40) {
                ctx.beginPath();
                ctx.moveTo(x, 0);
                ctx.lineTo(x, canvas.height);
                ctx.stroke();
            }
            for (let y = 0; y < canvas.height; y += 40) {
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(canvas.width, y);
                ctx.stroke();
            }

            drawWorldMap();

            // Draw threat markers with pulse effect
            threats.forEach((threat) => {
                threat.pulse += 0.05;
                const radius = 3 + Math.sin(threat.pulse) * 2;

                // Glow
                const gradient = ctx.createRadialGradient(
                    threat.x, threat.y, 0,
                    threat.x, threat.y, radius * 3
                );

                const color = threat.severity === 'CRITICAL' ? '#ff0000' :
                              threat.severity === 'HIGH' ? '#ff8800' :
                              threat.severity === 'MEDIUM' ? '#ffff00' : '#00ff00';

                gradient.addColorStop(0, color);
                gradient.addColorStop(1, 'transparent');

                ctx.fillStyle = gradient;
                ctx.beginPath();
                ctx.arc(threat.x, threat.y, radius * 3, 0, Math.PI * 2);
                ctx.fill();

                // Core
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(threat.x, threat.y, radius, 0, Math.PI * 2);
                ctx.fill();

                // Connecting lines (cyber effect)
                ctx.strokeStyle = 'rgba(0, 255, 65, 0.2)';
                ctx.lineWidth = 0.5;
                threats.forEach((other) => {
                    const dist = Math.hypot(other.x - threat.x, other.y - threat.y);
                    if (dist < 100) {
                        ctx.beginPath();
                        ctx.moveTo(threat.x, threat.y);
                        ctx.lineTo(other.x, other.y);
                        ctx.stroke();
                    }
                });
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
                <span style={{ marginRight: '10px' }}>🌍</span>
                GLOBAL THREAT MAP
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
                <span style={{ color: '#ff0000' }}>● CRITICAL</span>
                <span style={{ color: '#ff8800' }}>● HIGH</span>
                <span style={{ color: '#ffff00' }}>● MEDIUM</span>
                <span style={{ color: '#00ff00' }}>● LOW</span>
            </Box>
        </Box>
    );
};

export default ThreatMap;
