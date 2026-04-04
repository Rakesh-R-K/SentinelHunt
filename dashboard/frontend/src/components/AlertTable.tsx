import React, { useState } from 'react';
import {
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Collapse,
  Box,
} from '@mui/material';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowUpIcon from '@mui/icons-material/KeyboardArrowUp';
import { format } from 'date-fns';

interface Alert {
  alert_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  severity: string;
  threat_label: string;
  final_threat_score: number;
  confidence: number;
  reason: string;
}

interface AlertTableProps {
  alerts: Alert[];
  loading?: boolean;
  onAlertClick?: (alertId: string) => void;
}

const Row: React.FC<{ alert: Alert; onAlertClick?: (alertId: string) => void }> = ({ alert, onAlertClick }) => {
  const [open, setOpen] = useState(false);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'default';
      default: return 'default';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      return format(new Date(timestamp), 'MMM dd, HH:mm:ss');
    } catch {
      return timestamp;
    }
  };

  return (
    <>
      <TableRow 
        sx={{ 
          '& > *': { borderBottom: 'unset' }, 
          cursor: 'pointer',
          '&:hover': {
            background: 'rgba(100, 255, 218, 0.05)',
          }
        }} 
        hover
        onClick={() => onAlertClick && onAlertClick(alert.alert_id)}
      >
        <TableCell>
          <IconButton 
            size="small" 
            onClick={() => setOpen(!open)}
            sx={{ color: '#64ffda' }}
          >
            {open ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
          </IconButton>
        </TableCell>
        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{alert.alert_id}</TableCell>
        <TableCell sx={{ fontSize: '0.875rem' }}>{formatTimestamp(alert.timestamp)}</TableCell>
        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{alert.src_ip}</TableCell>
        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{alert.dst_ip}</TableCell>
        <TableCell>
          <Chip 
            label={alert.severity} 
            color={getSeverityColor(alert.severity)} 
            size="small"
            sx={{ 
              fontWeight: 600,
              fontSize: '0.75rem'
            }}
          />
        </TableCell>
        <TableCell sx={{ fontSize: '0.875rem' }}>{alert.threat_label}</TableCell>
        <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem' }}>{(alert.final_threat_score * 100).toFixed(1)}%</TableCell>
      </TableRow>
      <TableRow>
        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            <Box sx={{ 
              margin: 2, 
              p: 2, 
              bgcolor: 'rgba(100, 255, 218, 0.05)', 
              borderRadius: 2,
              border: '1px solid rgba(100, 255, 218, 0.2)'
            }}>
              <Typography variant="subtitle2" gutterBottom sx={{ 
                color: '#64ffda',
                fontWeight: 600
              }}>
                Alert Details
              </Typography>
              <Typography variant="body2" paragraph sx={{ color: '#ccd6f6' }}>
                <strong>Confidence:</strong> {(alert.confidence * 100).toFixed(1)}%
              </Typography>
              <Typography variant="body2" paragraph sx={{ color: '#ccd6f6' }}>
                <strong>Reason:</strong> {alert.reason}
              </Typography>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
};

const AlertTable: React.FC<AlertTableProps> = ({ alerts, loading, onAlertClick }) => {
  return (
    <Paper sx={{ 
      p: 0,
      background: 'transparent',
      boxShadow: 'none'
    }}>
      <TableContainer sx={{ 
        maxHeight: 600,
        borderRadius: '8px',
        border: '1px solid rgba(100, 255, 218, 0.1)'
      }}>
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda'
              }} />
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Alert ID</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Timestamp</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Source IP</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Destination IP</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Severity</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Threat Type</TableCell>
              <TableCell sx={{ 
                background: 'rgba(17, 34, 64, 0.95)',
                borderBottom: '2px solid rgba(100, 255, 218, 0.2)',
                fontWeight: 600,
                color: '#64ffda',
                fontSize: '0.875rem'
              }}>Threat Score</TableCell>
            </TableRow>
          </TableHead>
          <TableBody sx={{ 
            '& .MuiTableRow-root:nth-of-type(odd)': {
              background: 'rgba(0, 0, 0, 0.3)'
            },
            '& .MuiTableRow-root:nth-of-type(even)': {
              background: 'rgba(0, 0, 0, 0.5)'
            }
          }}>
            {alerts.map((alert) => (
              <Row key={alert.alert_id} alert={alert} onAlertClick={onAlertClick} />
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  );
};

export default AlertTable;
