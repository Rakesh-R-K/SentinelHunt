import React, { useState, useEffect } from 'react';
import { Box, Typography } from '@mui/material';

const BootSequence: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
    const [lines, setLines] = useState<string[]>([]);
    const [currentIndex, setCurrentIndex] = useState(0);

    const bootLines = [
        '> INITIALIZING SENTINELHUNT SYSTEM...',
        '> LOADING KERNEL MODULES.........................[OK]',
        '> STARTING ANOMALY DETECTION ENGINE..............[OK]',
        '> CONNECTING TO THREAT INTELLIGENCE FEED.........[OK]',
        '> SYSTEM STATUS: OPERATIONAL',
        '> WELCOME, OPERATOR',
        '',
        '> ENTERING HUNT MODE...',
    ];

    useEffect(() => {
        if (currentIndex < bootLines.length) {
            const timer = setTimeout(() => {
                setLines(prev => [...prev, bootLines[currentIndex]]);
                setCurrentIndex(prev => prev + 1);
            }, 80); // Faster boot sequence
            return () => clearTimeout(timer);
        } else {
            const completeTimer = setTimeout(() => {
                onComplete();
            }, 500);
            return () => clearTimeout(completeTimer);
        }
    }, [currentIndex, bootLines, onComplete]);

    return (
        <Box sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            backgroundColor: '#000000',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 4
        }}>
            <Box sx={{
                maxWidth: '800px',
                width: '100%',
                fontFamily: '"Share Tech Mono", "Fira Code", monospace',
                fontSize: '0.9rem'
            }}>
                {lines.map((line, index) => (
                    <Typography
                        key={index}
                        sx={{
                            color: line.includes('[OK]') ? '#00ff41' :
                                   line.includes('ELEVATED') ? '#ff8800' :
                                   line.includes('OPERATIONAL') ? '#00ffff' :
                                   line.includes('█') ? '#00ff41' :
                                   line.includes('WELCOME') ? '#ff0080' :
                                   '#00ff41',
                            textShadow: '0 0 5px currentColor',
                            marginBottom: line === '' ? '10px' : '2px',
                            fontFamily: 'inherit',
                            fontSize: line.includes('█') ? '0.6rem' : 'inherit',
                            letterSpacing: line.includes('█') ? '0' : '0.5px',
                            animation: index === lines.length - 1 ? 'blink 0.5s infinite' : 'none'
                        }}
                    >
                        {line}
                    </Typography>
                ))}
                <Typography sx={{
                    color: '#00ff41',
                    display: 'inline-block',
                    animation: 'blink 1s infinite'
                }}>
                    _
                </Typography>
            </Box>
        </Box>
    );
};

export default BootSequence;
