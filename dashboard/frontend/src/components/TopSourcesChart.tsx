import React, { useState, useEffect } from 'react';
import { Paper, Typography, Box } from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { fetchTopSources } from '../services/api';

const TopSourcesChart: React.FC = () => {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const chartData = await fetchTopSources();
      const formatted = chartData.labels.map((label: string, index: number) => ({
        ip: label,
        count: chartData.data[index],
      }));
      setData(formatted);
    } catch (error) {
      console.error('Error loading top sources chart:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Paper sx={{ p: 3, height: '400px' }}>
      <Typography variant="h6" gutterBottom>
        Top Attacking Sources
      </Typography>
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
          <Typography color="text.secondary">Loading...</Typography>
        </Box>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2d3561" />
            <XAxis 
              dataKey="ip" 
              stroke="#888"
              style={{ fontSize: '11px' }}
              angle={-45}
              textAnchor="end"
              height={80}
            />
            <YAxis 
              stroke="#888"
              style={{ fontSize: '12px' }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1a1f3a', 
                border: '1px solid #ff1744',
                borderRadius: '4px' 
              }} 
            />
            <Bar 
              dataKey="count" 
              fill="#ff1744"
              radius={[8, 8, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      )}
    </Paper>
  );
};

export default TopSourcesChart;
