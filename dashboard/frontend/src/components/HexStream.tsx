import React, { useEffect, useRef } from 'react';

const HexStream: React.FC = () => {
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const container = containerRef.current;
        if (!container) return;

        const createHexStream = () => {
            const stream = document.createElement('div');
            stream.style.position = 'absolute';
            stream.style.left = `${Math.random() * 100}%`;
            stream.style.top = '-20px';
            stream.style.color = Math.random() > 0.7 ? '#ff0080' : '#00ff41';
            stream.style.fontFamily = '"Fira Code", monospace';
            stream.style.fontSize = '10px';
            stream.style.opacity = '0.6';
            stream.style.textShadow = '0 0 3px currentColor';
            stream.style.pointerEvents = 'none';
            
            const hexChars = '0123456789ABCDEF';
            let hexString = '0x';
            for (let i = 0; i < 4; i++) {
                hexString += hexChars[Math.floor(Math.random() * 16)];
            }
            stream.textContent = hexString;

            container.appendChild(stream);

            const duration = 3000 + Math.random() * 2000;
            const animation = stream.animate([
                { transform: 'translateY(0)', opacity: 0.6 },
                { transform: `translateY(${window.innerHeight}px)`, opacity: 0 }
            ], {
                duration,
                easing: 'linear'
            });

            animation.onfinish = () => {
                stream.remove();
            };
        };

        const interval = setInterval(createHexStream, 200);
        return () => clearInterval(interval);
    }, []);

    return (
        <div
            ref={containerRef}
            style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                pointerEvents: 'none',
                zIndex: 5,
                overflow: 'hidden'
            }}
        />
    );
};

export default HexStream;
