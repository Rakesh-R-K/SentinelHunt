import React, { useState, useEffect } from 'react';
import { Paper, Typography, Box } from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { fetchSeverityChart } from '../services/api';

const SeverityChart: React.FC = () => {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const chartData = await fetchSeverityChart();
      const formatted = chartData.labels.map((label: string, index: number) => ({
        name: label,
        value: chartData.data[index],
      }));
      setData(formatted);
    } catch (error) {
      console.error('Error loading severity chart:', error);
    } finally {
      setLoading(false);
    }
  };

  const COLORS = {
    CRITICAL: '#ff1744',
    HIGH: '#ffc400',
    MEDIUM: '#00e5ff',
    LOW: '#888888',
  };

  return (
    <Paper sx={{ p: 3, height: '400px' }}>
      <Typography variant="h6" gutterBottom>
        Severity Distribution
      </Typography>
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
          <Typography color="text.secondary">Loading...</Typography>
        </Box>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS]} />
              ))}
            </Pie>
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1a1f3a', 
                border: '1px solid #00e5ff',
                borderRadius: '4px' 
              }} 
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </Paper>
  );
};

export default SeverityChart;
