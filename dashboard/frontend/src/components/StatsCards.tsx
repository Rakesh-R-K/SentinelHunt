import React from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import DevicesIcon from '@mui/icons-material/Devices';

interface Stats {
  total_alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unique_sources: number;
  unique_destinations: number;
  avg_threat_score: string;
}

interface StatsCardsProps {
  stats: Stats;
}

const StatsCards: React.FC<StatsCardsProps> = ({ stats }) => {
  const cards = [
    {
      title: 'Total Alerts',
      value: stats.total_alerts,
      icon: <InfoOutlinedIcon sx={{ fontSize: 40 }} />,
      color: '#64ffda',
      bgColor: 'rgba(100, 255, 218, 0.1)',
    },
    {
      title: 'Critical',
      value: stats.critical,
      icon: <ErrorOutlineIcon sx={{ fontSize: 40 }} />,
      color: '#ff5370',
      bgColor: 'rgba(255, 83, 112, 0.1)',
    },
    {
      title: 'High Severity',
      value: stats.high,
      icon: <WarningAmberIcon sx={{ fontSize: 40 }} />,
      color: '#ffcb6b',
      bgColor: 'rgba(255, 203, 107, 0.1)',
    },
    {
      title: 'Unique Sources',
      value: stats.unique_sources,
      icon: <DevicesIcon sx={{ fontSize: 40 }} />,
      color: '#c3e88d',
      bgColor: 'rgba(195, 232, 141, 0.1)',
    },
  ];

  return (
    <Grid container spacing={3}>
      {cards.map((card, index) => (
        <Grid item xs={12} sm={6} md={3} key={index}>
          <Paper
            sx={{
              p: 3,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: card.bgColor,
              backdropFilter: 'blur(10px)',
              border: `1px solid ${card.color}40`,
              borderRadius: '12px',
              transition: 'all 0.3s ease',
              boxShadow: `0 4px 20px ${card.color}20`,
              '&:hover': {
                transform: 'translateY(-4px)',
                boxShadow: `0 8px 30px ${card.color}40`,
                border: `1px solid ${card.color}`,
              },
            }}
          >
            <Box>
              <Typography 
                variant="body2" 
                sx={{ 
                  color: 'rgba(204, 214, 246, 0.7)',
                  fontSize: '0.875rem',
                  mb: 1,
                  fontWeight: 500
                }}
              >
                {card.title}
              </Typography>
              <Typography 
                variant="h3" 
                sx={{ 
                  color: card.color, 
                  fontWeight: 700
                }}
              >
                {card.value}
              </Typography>
            </Box>
            <Box sx={{ color: card.color, opacity: 0.8 }}>
              {card.icon}
            </Box>
          </Paper>
        </Grid>
      ))}
    </Grid>
  );
};

export default StatsCards;
