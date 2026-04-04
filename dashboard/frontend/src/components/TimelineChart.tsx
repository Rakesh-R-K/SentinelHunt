import React, { useState, useEffect } from 'react';
import { Paper, Typography, Box } from '@mui/material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { fetchTimelineChart } from '../services/api';

const TimelineChart: React.FC = () => {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const chartData = await fetchTimelineChart();
      const formatted = chartData.labels.map((label: string, index: number) => ({
        time: label.substring(11), // Extract HH from YYYY-MM-DDTHH
        alerts: chartData.data[index],
      }));
      setData(formatted);
    } catch (error) {
      console.error('Error loading timeline chart:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Paper sx={{ p: 3, height: '400px' }}>
      <Typography variant="h6" gutterBottom>
        Alert Timeline
      </Typography>
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
          <Typography color="text.secondary">Loading...</Typography>
        </Box>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2d3561" />
            <XAxis 
              dataKey="time" 
              stroke="#888"
              style={{ fontSize: '12px' }}
            />
            <YAxis 
              stroke="#888"
              style={{ fontSize: '12px' }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1a1f3a', 
                border: '1px solid #00e5ff',
                borderRadius: '4px' 
              }} 
            />
            <Line 
              type="monotone" 
              dataKey="alerts" 
              stroke="#00e5ff" 
              strokeWidth={2}
              dot={{ fill: '#00e5ff', r: 4 }}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </Paper>
  );
};

export default TimelineChart;
