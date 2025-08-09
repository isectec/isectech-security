'use client';

import React, { useState, useCallback, useMemo } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardHeader,
  IconButton,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  LinearProgress,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  useTheme,
  useMediaQuery
} from '@mui/material';
import {
  Close as CloseIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Timeline as TimelineIcon,
  Assessment as AssessmentIcon,
  Security as SecurityIcon,
  Business as BusinessIcon,
  ExpandMore as ExpandMoreIcon,
  Download as DownloadIcon,
  Share as ShareIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon
} from '@mui/icons-material';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ChartTooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { format, subDays, parseISO } from 'date-fns';

interface ExecutiveDrillDownProps {
  open: boolean;
  onClose: () => void;
  drillDownType: DrillDownType;
  data: any;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  title: string;
  subtitle?: string;
}

type DrillDownType = 
  | 'security-posture' 
  | 'threat-landscape' 
  | 'compliance-status' 
  | 'roi-metrics' 
  | 'predictive-analytics'
  | 'incident-response'
  | 'vulnerability-management';

interface DrillDownData {
  overview: {
    currentValue: number;
    previousValue: number;
    trend: 'up' | 'down' | 'stable';
    trendPercentage: number;
    confidenceScore?: number;
    lastUpdated: Date;
  };
  historicalData: HistoricalDataPoint[];
  breakdown: BreakdownItem[];
  recommendations: RecommendationItem[];
  relatedMetrics: RelatedMetric[];
  detailTables: DetailTable[];
}

interface HistoricalDataPoint {
  date: string;
  value: number;
  target?: number;
  benchmark?: number;
  annotations?: string[];
}

interface BreakdownItem {
  category: string;
  value: number;
  percentage: number;
  status: 'good' | 'warning' | 'critical' | 'unknown';
  description: string;
  trend?: 'up' | 'down' | 'stable';
}

interface RecommendationItem {
  id: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  impact: string;
  effort: string;
  timeline: string;
  businessValue: number;
  riskReduction: number;
}

interface RelatedMetric {
  name: string;
  value: number | string;
  unit?: string;
  status: 'good' | 'warning' | 'critical';
  description: string;
}

interface DetailTable {
  title: string;
  columns: TableColumn[];
  rows: TableRow[];
  totalRows?: number;
}

interface TableColumn {
  id: string;
  label: string;
  align?: 'left' | 'center' | 'right';
  format?: (value: any) => string;
}

interface TableRow {
  [key: string]: any;
}

const COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7300', '#8dd1e1', '#d084d0'];

export const ExecutiveDrillDown: React.FC<ExecutiveDrillDownProps> = ({
  open,
  onClose,
  drillDownType,
  data,
  userRole,
  title,
  subtitle
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  const [activeTab, setActiveTab] = useState(0);
  const [tablePages, setTablePages] = useState<Record<string, number>>({});
  const [tableRowsPerPage, setTableRowsPerPage] = useState<Record<string, number>>({});

  // Process drill-down data based on type and role
  const drillDownData: DrillDownData = useMemo(() => {
    return generateDrillDownData(drillDownType, data, userRole);
  }, [drillDownType, data, userRole]);

  const handleTabChange = useCallback((event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  }, []);

  const handleTablePageChange = useCallback((tableId: string) => (
    event: unknown,
    newPage: number
  ) => {
    setTablePages(prev => ({ ...prev, [tableId]: newPage }));
  }, []);

  const handleTableRowsPerPageChange = useCallback((tableId: string) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const newRowsPerPage = parseInt(event.target.value, 10);
    setTableRowsPerPage(prev => ({ ...prev, [tableId]: newRowsPerPage }));
    setTablePages(prev => ({ ...prev, [tableId]: 0 }));
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good': return theme.palette.success.main;
      case 'warning': return theme.palette.warning.main;
      case 'critical': return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'good': return <CheckCircleIcon />;
      case 'warning': return <WarningIcon />;
      case 'critical': return <ErrorIcon />;
      default: return <InfoIcon />;
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUpIcon color="success" />;
      case 'down': return <TrendingDownIcon color="error" />;
      default: return <TimelineIcon color="action" />;
    }
  };

  const formatValue = (value: number, type: string) => {
    switch (type) {
      case 'percentage':
        return `${value.toFixed(1)}%`;
      case 'currency':
        return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value);
      case 'time':
        return `${value} minutes`;
      default:
        return value.toString();
    }
  };

  const TabPanel = ({ children, value, index }: any) => (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && (
        <Box sx={{ py: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="xl"
      fullWidth
      fullScreen={isMobile}
      PaperProps={{
        sx: { minHeight: '80vh', maxHeight: '95vh' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h6" component="h2">
              {title} - Detailed Analysis
            </Typography>
            {subtitle && (
              <Typography variant="body2" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton size="small" title="Export Data">
              <DownloadIcon />
            </IconButton>
            <IconButton size="small" title="Share Analysis">
              <ShareIcon />
            </IconButton>
            <IconButton size="small" title="Refresh Data">
              <RefreshIcon />
            </IconButton>
            <IconButton onClick={onClose} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent>
        <Box sx={{ width: '100%' }}>
          {/* Overview Cards */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
                    {formatValue(drillDownData.overview.currentValue, drillDownType)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Current Value
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    {getTrendIcon(drillDownData.overview.trend)}
                    <Typography
                      variant="body2"
                      color={drillDownData.overview.trend === 'up' ? 'success.main' : 
                             drillDownData.overview.trend === 'down' ? 'error.main' : 'text.secondary'}
                      sx={{ ml: 0.5 }}
                    >
                      {drillDownData.overview.trendPercentage}%
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
                    {formatValue(drillDownData.overview.previousValue, drillDownType)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Previous Period
                  </Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    Last 30 days
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {drillDownData.overview.confidenceScore && userRole !== 'board_member' && (
              <Grid item xs={12} sm={6} md={3}>
                <Card>
                  <CardContent>
                    <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
                      {Math.round(drillDownData.overview.confidenceScore * 100)}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Confidence Score
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={drillDownData.overview.confidenceScore * 100}
                      sx={{ mt: 1 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
            )}

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography variant="body1" sx={{ mb: 1, fontWeight: 'bold' }}>
                    Last Updated
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {format(drillDownData.overview.lastUpdated, 'MMM dd, yyyy HH:mm')}
                  </Typography>
                  <Chip 
                    label="Real-time" 
                    size="small" 
                    color="success" 
                    variant="outlined"
                    sx={{ mt: 1 }}
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Tabs */}
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs 
              value={activeTab} 
              onChange={handleTabChange}
              variant={isMobile ? "scrollable" : "fullWidth"}
              scrollButtons="auto"
            >
              <Tab label="Trend Analysis" icon={<TimelineIcon />} />
              <Tab label="Breakdown" icon={<AssessmentIcon />} />
              <Tab label="Recommendations" icon={<BusinessIcon />} />
              {userRole !== 'board_member' && (
                <Tab label="Detailed Data" icon={<FilterIcon />} />
              )}
            </Tabs>
          </Box>

          {/* Trend Analysis Tab */}
          <TabPanel value={activeTab} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Card>
                  <CardHeader title="Historical Trend" />
                  <CardContent>
                    <ResponsiveContainer width="100%" height={300}>
                      <AreaChart data={drillDownData.historicalData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis 
                          dataKey="date" 
                          tickFormatter={(value) => format(parseISO(value), 'MMM dd')}
                        />
                        <YAxis />
                        <ChartTooltip 
                          labelFormatter={(value) => format(parseISO(value), 'MMM dd, yyyy')}
                          formatter={(value: any) => [formatValue(value, drillDownType), 'Value']}
                        />
                        <Legend />
                        <Area
                          type="monotone"
                          dataKey="value"
                          stroke={theme.palette.primary.main}
                          fill={theme.palette.primary.light}
                          fillOpacity={0.6}
                        />
                        {drillDownData.historicalData[0]?.target && (
                          <Line
                            type="monotone"
                            dataKey="target"
                            stroke={theme.palette.success.main}
                            strokeDasharray="5 5"
                            dot={false}
                          />
                        )}
                        {drillDownData.historicalData[0]?.benchmark && (
                          <Line
                            type="monotone"
                            dataKey="benchmark"
                            stroke={theme.palette.warning.main}
                            strokeDasharray="3 3"
                            dot={false}
                          />
                        )}
                      </AreaChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </Grid>

              {/* Related Metrics */}
              <Grid item xs={12}>
                <Card>
                  <CardHeader title="Related Metrics" />
                  <CardContent>
                    <Grid container spacing={2}>
                      {drillDownData.relatedMetrics.map((metric, index) => (
                        <Grid item xs={12} sm={6} md={4} key={index}>
                          <Box
                            sx={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 2,
                              p: 2,
                              border: '1px solid',
                              borderColor: 'divider',
                              borderRadius: 1,
                              bgcolor: `${getStatusColor(metric.status)}10`
                            }}
                          >
                            {getStatusIcon(metric.status)}
                            <Box sx={{ flex: 1 }}>
                              <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                                {typeof metric.value === 'number' ? 
                                  formatValue(metric.value, drillDownType) : 
                                  metric.value
                                }
                                {metric.unit && ` ${metric.unit}`}
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                {metric.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {metric.description}
                              </Typography>
                            </Box>
                          </Box>
                        </Grid>
                      ))}
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Breakdown Tab */}
          <TabPanel value={activeTab} index={1}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardHeader title="Distribution" />
                  <CardContent>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={drillDownData.breakdown}
                          cx="50%"
                          cy="50%"
                          outerRadius={80}
                          dataKey="value"
                          nameKey="category"
                          label={({ category, percentage }) => `${category}: ${percentage}%`}
                        >
                          {drillDownData.breakdown.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <ChartTooltip 
                          formatter={(value: any) => [formatValue(value, drillDownType), 'Value']}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={6}>
                <Card>
                  <CardHeader title="Category Breakdown" />
                  <CardContent>
                    <List>
                      {drillDownData.breakdown.map((item, index) => (
                        <React.Fragment key={index}>
                          <ListItem>
                            <ListItemIcon sx={{ color: getStatusColor(item.status) }}>
                              {getStatusIcon(item.status)}
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                  <Typography variant="body1">
                                    {item.category}
                                  </Typography>
                                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                                      {formatValue(item.value, drillDownType)} ({item.percentage}%)
                                    </Typography>
                                    {item.trend && getTrendIcon(item.trend)}
                                  </Box>
                                </Box>
                              }
                              secondary={item.description}
                            />
                          </ListItem>
                          {index < drillDownData.breakdown.length - 1 && <Divider />}
                        </React.Fragment>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Recommendations Tab */}
          <TabPanel value={activeTab} index={2}>
            <Grid container spacing={2}>
              {drillDownData.recommendations.map((rec, index) => (
                <Grid item xs={12} md={6} key={rec.id}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                        <Typography variant="h6" sx={{ flex: 1 }}>
                          {rec.title}
                        </Typography>
                        <Chip
                          label={rec.priority.toUpperCase()}
                          size="small"
                          color={rec.priority === 'critical' ? 'error' : 
                                 rec.priority === 'high' ? 'warning' : 
                                 rec.priority === 'medium' ? 'primary' : 'default'}
                        />
                      </Box>
                      
                      <Typography variant="body2" sx={{ mb: 2 }}>
                        {rec.description}
                      </Typography>
                      
                      <Accordion variant="outlined">
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="body2">Details</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Grid container spacing={2}>
                            <Grid item xs={6}>
                              <Typography variant="caption" color="text.secondary">
                                Business Impact
                              </Typography>
                              <Typography variant="body2">
                                {rec.impact}
                              </Typography>
                            </Grid>
                            <Grid item xs={6}>
                              <Typography variant="caption" color="text.secondary">
                                Implementation Effort
                              </Typography>
                              <Typography variant="body2">
                                {rec.effort}
                              </Typography>
                            </Grid>
                            <Grid item xs={6}>
                              <Typography variant="caption" color="text.secondary">
                                Timeline
                              </Typography>
                              <Typography variant="body2">
                                {rec.timeline}
                              </Typography>
                            </Grid>
                            <Grid item xs={6}>
                              <Typography variant="caption" color="text.secondary">
                                Risk Reduction
                              </Typography>
                              <Typography variant="body2">
                                {rec.riskReduction}%
                              </Typography>
                            </Grid>
                          </Grid>
                          
                          <Box sx={{ mt: 2 }}>
                            <LinearProgress
                              variant="determinate"
                              value={rec.businessValue}
                              sx={{ height: 8, borderRadius: 4 }}
                            />
                            <Typography variant="caption" color="text.secondary">
                              Business Value Score: {rec.businessValue}/100
                            </Typography>
                          </Box>
                        </AccordionDetails>
                      </Accordion>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Detailed Data Tab */}
          {userRole !== 'board_member' && (
            <TabPanel value={activeTab} index={3}>
              {drillDownData.detailTables.map((table, tableIndex) => (
                <Card key={tableIndex} sx={{ mb: 3 }}>
                  <CardHeader title={table.title} />
                  <CardContent sx={{ p: 0 }}>
                    <TableContainer>
                      <Table>
                        <TableHead>
                          <TableRow>
                            {table.columns.map((column) => (
                              <TableCell
                                key={column.id}
                                align={column.align || 'left'}
                              >
                                {column.label}
                              </TableCell>
                            ))}
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {table.rows
                            .slice(
                              (tablePages[table.title] || 0) * (tableRowsPerPage[table.title] || 10),
                              (tablePages[table.title] || 0) * (tableRowsPerPage[table.title] || 10) + (tableRowsPerPage[table.title] || 10)
                            )
                            .map((row, rowIndex) => (
                              <TableRow key={rowIndex}>
                                {table.columns.map((column) => (
                                  <TableCell
                                    key={column.id}
                                    align={column.align || 'left'}
                                  >
                                    {column.format ? column.format(row[column.id]) : row[column.id]}
                                  </TableCell>
                                ))}
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                    <TablePagination
                      rowsPerPageOptions={[5, 10, 25]}
                      component="div"
                      count={table.totalRows || table.rows.length}
                      rowsPerPage={tableRowsPerPage[table.title] || 10}
                      page={tablePages[table.title] || 0}
                      onPageChange={handleTablePageChange(table.title)}
                      onRowsPerPageChange={handleTableRowsPerPageChange(table.title)}
                    />
                  </CardContent>
                </Card>
              ))}
            </TabPanel>
          )}
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Close</Button>
        <Button variant="contained" startIcon={<DownloadIcon />}>
          Export Analysis
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// Generate mock drill-down data based on type and role
function generateDrillDownData(type: DrillDownType, data: any, userRole: string): DrillDownData {
  const baseData = {
    overview: {
      currentValue: Math.floor(Math.random() * 100) + 50,
      previousValue: Math.floor(Math.random() * 100) + 40,
      trend: ['up', 'down', 'stable'][Math.floor(Math.random() * 3)] as 'up' | 'down' | 'stable',
      trendPercentage: Math.floor(Math.random() * 20) + 5,
      confidenceScore: userRole !== 'board_member' ? Math.random() * 0.3 + 0.7 : undefined,
      lastUpdated: new Date()
    },
    historicalData: Array.from({ length: 30 }, (_, i) => ({
      date: format(subDays(new Date(), 29 - i), 'yyyy-MM-dd'),
      value: Math.floor(Math.random() * 20) + 70 + Math.sin(i / 5) * 10,
      target: type === 'security-posture' ? 85 : undefined,
      benchmark: type === 'roi-metrics' ? 75 : undefined
    })),
    breakdown: [
      { category: 'Network Security', value: 85, percentage: 35, status: 'good' as const, description: 'Firewall and intrusion detection', trend: 'up' as const },
      { category: 'Application Security', value: 72, percentage: 28, status: 'warning' as const, description: 'Code scanning and WAF', trend: 'stable' as const },
      { category: 'Identity & Access', value: 91, percentage: 25, status: 'good' as const, description: 'Authentication and authorization', trend: 'up' as const },
      { category: 'Data Protection', value: 68, percentage: 12, status: 'critical' as const, description: 'Encryption and DLP', trend: 'down' as const }
    ],
    recommendations: [
      {
        id: '1',
        priority: 'high' as const,
        title: 'Implement Zero Trust Architecture',
        description: 'Deploy comprehensive zero trust security model across all network segments',
        impact: 'High - Significant reduction in lateral movement risks',
        effort: 'High - 6-12 months implementation',
        timeline: '2-3 quarters',
        businessValue: 85,
        riskReduction: 40
      },
      {
        id: '2',
        priority: 'medium' as const,
        title: 'Enhanced Security Awareness Training',
        description: 'Implement comprehensive security training program for all employees',
        impact: 'Medium - Reduced human error incidents',
        effort: 'Low - 1-2 months setup',
        timeline: '1 quarter',
        businessValue: 70,
        riskReduction: 25
      }
    ],
    relatedMetrics: [
      { name: 'Mean Time to Detection', value: 15, unit: 'minutes', status: 'good' as const, description: 'Average time to identify security incidents' },
      { name: 'Vulnerability Patch Rate', value: 94, unit: '%', status: 'good' as const, description: 'Percentage of vulnerabilities patched within SLA' },
      { name: 'Security Training Completion', value: 87, unit: '%', status: 'warning' as const, description: 'Employee security training completion rate' }
    ],
    detailTables: [
      {
        title: 'Security Control Effectiveness',
        columns: [
          { id: 'control', label: 'Security Control' },
          { id: 'score', label: 'Effectiveness Score', align: 'right' as const, format: (value: number) => `${value}%` },
          { id: 'coverage', label: 'Coverage', align: 'right' as const, format: (value: number) => `${value}%` },
          { id: 'status', label: 'Status' }
        ],
        rows: [
          { control: 'Network Firewall', score: 92, coverage: 100, status: 'Active' },
          { control: 'Endpoint Protection', score: 88, coverage: 95, status: 'Active' },
          { control: 'Email Security', score: 85, coverage: 100, status: 'Active' },
          { control: 'Web Application Firewall', score: 78, coverage: 85, status: 'Partial' }
        ]
      }
    ]
  };

  return baseData;
}

export default ExecutiveDrillDown;