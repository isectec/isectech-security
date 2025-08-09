'use client';

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  LinearProgress,
  Alert,
  AlertTitle,
  IconButton,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useTheme,
  useMediaQuery
} from '@mui/material';
import {
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Business as BusinessIcon,
  Gavel as ComplianceIcon,
  Psychology as PredictiveIcon,
  Schedule as ScheduleIcon,
  Assignment as TaskIcon,
  MonetizationOn as InvestmentIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  PriorityHigh as PriorityIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { formatDistanceToNow, format } from 'date-fns';

interface ExecutivePredictiveAnalyticsProps {
  predictions: ExecutivePredictiveSnapshot | null;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  isLoading?: boolean;
  onPredictionClick?: (predictionId: string) => void;
  onRecommendationClick?: (recommendationId: string) => void;
  onInvestmentClick?: (investmentId: string) => void;
  className?: string;
}

interface ExecutivePredictiveSnapshot {
  generatedAt: string;
  validUntil: string;
  overallRiskScore: number;
  confidenceScore: number;
  threatPredictions: ThreatPrediction[];
  criticalThreats: CriticalThreatAlert[];
  businessRisks: BusinessRiskAssessment[];
  vulnerabilityRisks: VulnerabilityRiskPrediction[];
  financialForecasts: FinancialImpactForecast[];
  complianceRisks: ComplianceRiskPrediction[];
  auditReadiness: AuditReadinessAssessment[];
  immediateActions: ExecutiveRecommendation[];
  strategicRecommendations: ExecutiveRecommendation[];
  investmentRecommendations: InvestmentRecommendation[];
  modelAccuracy: Record<string, number>;
  predictionReliability: number;
}

interface ThreatPrediction {
  id: string;
  threatType: string;
  probability: number;
  confidenceLevel: number;
  timeHorizon: string;
  impactScore: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  attackVectors: string[];
}

interface CriticalThreatAlert {
  id: string;
  alertLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  threatType: string;
  predictedOccurrence: string;
  probability: number;
  executiveNotification: boolean;
  escalationRequired: boolean;
}

interface BusinessRiskAssessment {
  id: string;
  riskCategory: string;
  riskDescription: string;
  probability: number;
  businessImpact: number;
  financialImpact?: {
    minImpact: number;
    maxImpact: number;
    mostLikelyImpact: number;
    currency: string;
  };
  timeHorizon: string;
  confidenceLevel: number;
}

interface VulnerabilityRiskPrediction {
  id: string;
  assetType: string;
  vulnerabilityClass: string;
  exploitProbability: number;
  impactScore: number;
  affectedAssets: number;
  businessCriticality: number;
}

interface FinancialImpactForecast {
  scenarioName: string;
  probability: number;
  impactPrediction: {
    impactAmount: number;
    currency: string;
    confidenceLevel: number;
  };
  timeHorizon: string;
}

interface ComplianceRiskPrediction {
  id: string;
  framework: string;
  requirementName: string;
  violationProbability: number;
  complianceGap: number;
  potentialFines?: {
    minImpact: number;
    maxImpact: number;
    currency: string;
  };
  remediationTimeframe: string;
}

interface AuditReadinessAssessment {
  framework: string;
  readinessScore: number;
  gapAnalysis: string[];
  timeToReadiness: string;
}

interface ExecutiveRecommendation {
  id: string;
  type: 'IMMEDIATE' | 'STRATEGIC' | 'PREVENTIVE';
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  businessJustification: string;
  expectedOutcome: string;
  riskReduction: number;
  implementationTime: string;
  responsibleParty: string;
  executiveApprovalRequired: boolean;
  confidenceScore: number;
  generatedAt: string;
  validUntil: string;
}

interface InvestmentRecommendation {
  id: string;
  investmentType: string;
  title: string;
  description: string;
  businessCase: string;
  estimatedCost: {
    initialCost: number;
    ongoingCost: number;
    currency: string;
  };
  expectedROI: number;
  roiTimeframe: string;
  riskReduction: number;
  executiveSponsorshipRequired: boolean;
  boardApprovalRequired: boolean;
  confidenceLevel: number;
}

export const ExecutivePredictiveAnalytics: React.FC<ExecutivePredictiveAnalyticsProps> = ({
  predictions,
  userRole,
  isLoading = false,
  onPredictionClick,
  onRecommendationClick,
  onInvestmentClick,
  className
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  // State management
  const [selectedPrediction, setSelectedPrediction] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<string>('overview');
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState<any>(null);

  // Computed values
  const riskLevel = useMemo(() => {
    if (!predictions) return 'unknown';
    const score = predictions.overallRiskScore;
    if (score >= 0.8) return 'critical';
    if (score >= 0.6) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
  }, [predictions]);

  const prioritizedRecommendations = useMemo(() => {
    if (!predictions) return [];
    
    return [...predictions.immediateActions, ...predictions.strategicRecommendations]
      .sort((a, b) => {
        const priorityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0);
      })
      .slice(0, userRole === 'board_member' ? 3 : 8); // Limit for board members
  }, [predictions, userRole]);

  const topThreats = useMemo(() => {
    if (!predictions) return [];
    
    return [...predictions.threatPredictions, ...(predictions.criticalThreats || [])]
      .sort((a, b) => (b.probability || 0) - (a.probability || 0))
      .slice(0, userRole === 'board_member' ? 3 : 5);
  }, [predictions, userRole]);

  // Event handlers
  const handlePredictionClick = useCallback((predictionId: string) => {
    setSelectedPrediction(predictionId);
    if (onPredictionClick) {
      onPredictionClick(predictionId);
    }
  }, [onPredictionClick]);

  const handleDetailView = useCallback((item: any, type: string) => {
    setSelectedDetail({ ...item, type });
    setDetailDialogOpen(true);
  }, []);

  const handleAccordionChange = useCallback((section: string) => (event: React.SyntheticEvent, isExpanded: boolean) => {
    setExpandedSection(isExpanded ? section : '');
  }, []);

  // Utility functions
  const getRiskColor = (score: number) => {
    if (score >= 0.8) return theme.palette.error.main;
    if (score >= 0.6) return theme.palette.warning.main;
    if (score >= 0.4) return theme.palette.info.main;
    return theme.palette.success.main;
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return theme.palette.error.main;
      case 'HIGH': return theme.palette.warning.main;
      case 'MEDIUM': return theme.palette.info.main;
      default: return theme.palette.success.main;
    }
  };

  const formatCurrency = (amount: number, currency = 'USD') => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    }).format(amount);
  };

  const formatDuration = (duration: string) => {
    // Parse duration string and format for executive consumption
    return duration.replace('h', ' hours').replace('m', ' minutes').replace('d', ' days');
  };

  if (isLoading) {
    return (
      <Card className={className} sx={{ minHeight: 400 }}>
        <CardHeader
          title="Predictive Security Analytics"
          avatar={<PredictiveIcon />}
        />
        <CardContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {[...Array(4)].map((_, index) => (
              <Box key={index} sx={{ width: '100%' }}>
                <LinearProgress />
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Loading predictive models...
                </Typography>
              </Box>
            ))}
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (!predictions) {
    return (
      <Card className={className}>
        <CardHeader
          title="Predictive Security Analytics"
          avatar={<PredictiveIcon />}
        />
        <CardContent>
          <Alert severity="info">
            <AlertTitle>Predictive Analytics Unavailable</AlertTitle>
            Predictive models are currently initializing. Please check back in a few moments.
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box className={className}>
      {/* Executive Risk Overview */}
      <Card sx={{ mb: 2 }}>
        <CardHeader
          title="Predictive Risk Assessment"
          subtitle={`Generated ${formatDistanceToNow(new Date(predictions.generatedAt))} ago`}
          avatar={<PredictiveIcon color="primary" />}
          action={
            <Tooltip title="Prediction Confidence">
              <Chip
                label={`${Math.round(predictions.confidenceScore * 100)}% Confidence`}
                color={predictions.confidenceScore > 0.8 ? 'success' : predictions.confidenceScore > 0.6 ? 'warning' : 'error'}
                size="small"
              />
            </Tooltip>
          }
        />
        <CardContent>
          <Grid container spacing={3}>
            {/* Overall Risk Score */}
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" sx={{ color: getRiskColor(predictions.overallRiskScore), fontWeight: 'bold' }}>
                  {Math.round(predictions.overallRiskScore * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Overall Risk Level
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={predictions.overallRiskScore * 100}
                  sx={{ 
                    mt: 1, 
                    height: 8, 
                    borderRadius: 4,
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: getRiskColor(predictions.overallRiskScore)
                    }
                  }}
                />
              </Box>
            </Grid>

            {/* Model Reliability */}
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" sx={{ color: theme.palette.info.main, fontWeight: 'bold' }}>
                  {Math.round(predictions.predictionReliability * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Model Reliability
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={predictions.predictionReliability * 100}
                  color="info"
                  sx={{ mt: 1, height: 8, borderRadius: 4 }}
                />
              </Box>
            </Grid>

            {/* Critical Alerts Count */}
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" sx={{ 
                  color: predictions.criticalThreats?.length > 0 ? theme.palette.error.main : theme.palette.success.main, 
                  fontWeight: 'bold' 
                }}>
                  {predictions.criticalThreats?.length || 0}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Critical Threats Predicted
                </Typography>
                {predictions.criticalThreats?.length > 0 && (
                  <Chip
                    label="Immediate Action Required"
                    color="error"
                    size="small"
                    sx={{ mt: 1 }}
                  />
                )}
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Grid container spacing={2}>
        {/* Critical Threats and Immediate Actions */}
        <Grid item xs={12} lg={8}>
          <Accordion expanded={expandedSection === 'threats'} onChange={handleAccordionChange('threats')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ErrorIcon color="error" />
                <Typography variant="h6">
                  Critical Threats & Immediate Actions
                </Typography>
                {predictions.criticalThreats?.length > 0 && (
                  <Chip label={predictions.criticalThreats.length} color="error" size="small" />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <AnimatePresence>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  {/* Critical Threat Alerts */}
                  {predictions.criticalThreats && predictions.criticalThreats.length > 0 && (
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 'bold', color: theme.palette.error.main }}>
                        Critical Threat Alerts
                      </Typography>
                      <List>
                        {predictions.criticalThreats.slice(0, userRole === 'board_member' ? 2 : 4).map((threat) => (
                          <ListItem key={threat.id} sx={{ 
                            bgcolor: 'error.light', 
                            mb: 1, 
                            borderRadius: 1,
                            cursor: 'pointer',
                            '&:hover': { bgcolor: 'error.main', color: 'white' }
                          }}
                          onClick={() => handleDetailView(threat, 'threat')}
                          >
                            <ListItemIcon>
                              <WarningIcon color="error" />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                                  {threat.threatType} - {threat.alertLevel} Alert
                                </Typography>
                              }
                              secondary={
                                <Box>
                                  <Typography variant="body2" color="text.secondary">
                                    {Math.round(threat.probability * 100)}% probability
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    Predicted: {format(new Date(threat.predictedOccurrence), 'MMM dd, HH:mm')}
                                  </Typography>
                                </Box>
                              }
                            />
                            {threat.executiveNotification && (
                              <Chip label="Executive Alert" color="error" size="small" />
                            )}
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Immediate Actions */}
                  {predictions.immediateActions && predictions.immediateActions.length > 0 && (
                    <Box>
                      <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 'bold', color: theme.palette.warning.main }}>
                        Immediate Actions Required
                      </Typography>
                      <List>
                        {predictions.immediateActions.slice(0, userRole === 'board_member' ? 3 : 5).map((action) => (
                          <ListItem key={action.id} sx={{ 
                            bgcolor: 'warning.light', 
                            mb: 1, 
                            borderRadius: 1,
                            cursor: 'pointer',
                            '&:hover': { bgcolor: 'warning.main', color: 'white' }
                          }}
                          onClick={() => handleDetailView(action, 'recommendation')}
                          >
                            <ListItemIcon>
                              <PriorityIcon color="warning" />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                                  {action.title}
                                </Typography>
                              }
                              secondary={
                                <Box>
                                  <Typography variant="body2" color="text.secondary">
                                    {action.description}
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                    <Chip label={action.priority} size="small" color={
                                      action.priority === 'CRITICAL' ? 'error' : 
                                      action.priority === 'HIGH' ? 'warning' : 'info'
                                    } />
                                    <Chip label={formatDuration(action.implementationTime)} size="small" variant="outlined" />
                                    {action.executiveApprovalRequired && (
                                      <Chip label="Exec Approval" size="small" color="secondary" />
                                    )}
                                  </Box>
                                </Box>
                              }
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </motion.div>
              </AnimatePresence>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Business Impact Forecasts */}
        <Grid item xs={12} lg={4}>
          <Accordion expanded={expandedSection === 'business'} onChange={handleAccordionChange('business')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BusinessIcon color="primary" />
                <Typography variant="h6">Business Impact Forecasts</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {predictions.financialForecasts?.slice(0, userRole === 'board_member' ? 3 : 5).map((forecast, index) => (
                  <ListItem key={index} sx={{ px: 0 }}>
                    <ListItemText
                      primary={
                        <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                          {forecast.scenarioName}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            Probability: {Math.round(forecast.probability * 100)}%
                          </Typography>
                          <Typography variant="body2" sx={{ 
                            color: theme.palette.error.main, 
                            fontWeight: 'bold' 
                          }}>
                            Impact: {formatCurrency(forecast.impactPrediction.impactAmount, forecast.impactPrediction.currency)}
                          </Typography>
                          <LinearProgress
                            variant="determinate"
                            value={forecast.probability * 100}
                            sx={{ mt: 1, height: 4, borderRadius: 2 }}
                            color={forecast.probability > 0.5 ? 'error' : forecast.probability > 0.3 ? 'warning' : 'info'}
                          />
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Strategic Recommendations */}
        <Grid item xs={12} lg={6}>
          <Accordion expanded={expandedSection === 'strategic'} onChange={handleAccordionChange('strategic')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TimelineIcon color="primary" />
                <Typography variant="h6">Strategic Recommendations</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {predictions.strategicRecommendations?.slice(0, userRole === 'board_member' ? 3 : 6).map((recommendation) => (
                  <ListItem key={recommendation.id} sx={{ 
                    border: '1px solid', 
                    borderColor: 'divider', 
                    mb: 1, 
                    borderRadius: 1,
                    cursor: 'pointer',
                    '&:hover': { bgcolor: 'action.hover' }
                  }}
                  onClick={() => handleDetailView(recommendation, 'recommendation')}
                  >
                    <ListItemIcon>
                      <TaskIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                          {recommendation.title}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {recommendation.businessJustification}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                            <Chip 
                              label={recommendation.priority} 
                              size="small" 
                              color={getPriorityColor(recommendation.priority) === theme.palette.error.main ? 'error' : 'default'}
                            />
                            <Chip 
                              label={`${Math.round(recommendation.riskReduction * 100)}% Risk Reduction`} 
                              size="small" 
                              variant="outlined" 
                              color="success"
                            />
                          </Box>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Investment Recommendations */}
        <Grid item xs={12} lg={6}>
          <Accordion expanded={expandedSection === 'investments'} onChange={handleAccordionChange('investments')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <InvestmentIcon color="success" />
                <Typography variant="h6">Investment Opportunities</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {predictions.investmentRecommendations?.slice(0, userRole === 'board_member' ? 2 : 4).map((investment) => (
                  <ListItem key={investment.id} sx={{ 
                    border: '1px solid', 
                    borderColor: 'success.main', 
                    mb: 1, 
                    borderRadius: 1,
                    cursor: 'pointer',
                    '&:hover': { bgcolor: 'success.light', opacity: 0.8 }
                  }}
                  onClick={() => handleDetailView(investment, 'investment')}
                  >
                    <ListItemIcon>
                      <InvestmentIcon color="success" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                          {investment.title}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {investment.businessCase}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                            <Chip 
                              label={formatCurrency(investment.estimatedCost.initialCost, investment.estimatedCost.currency)} 
                              size="small" 
                              variant="outlined"
                            />
                            <Chip 
                              label={`${Math.round(investment.expectedROI * 100)}% ROI`} 
                              size="small" 
                              color="success"
                            />
                            {investment.boardApprovalRequired && (
                              <Chip label="Board Approval" size="small" color="warning" />
                            )}
                          </Box>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Compliance Risk Assessment */}
        {!isMobile && (
          <Grid item xs={12}>
            <Accordion expanded={expandedSection === 'compliance'} onChange={handleAccordionChange('compliance')}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ComplianceIcon color="info" />
                  <Typography variant="h6">Compliance Risk Assessment</Typography>
                  {predictions.complianceRisks && predictions.complianceRisks.some(risk => risk.violationProbability > 0.7) && (
                    <Chip label="High Risk" color="error" size="small" />
                  )}
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {predictions.complianceRisks?.slice(0, 6).map((risk) => (
                    <Grid item xs={12} md={6} key={risk.id}>
                      <Card variant="outlined" sx={{ 
                        cursor: 'pointer',
                        '&:hover': { boxShadow: theme.shadows[4] }
                      }}
                      onClick={() => handleDetailView(risk, 'compliance')}
                      >
                        <CardContent sx={{ pb: 2 }}>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                              {risk.framework}
                            </Typography>
                            <Chip 
                              label={`${Math.round(risk.violationProbability * 100)}%`}
                              size="small"
                              color={
                                risk.violationProbability > 0.7 ? 'error' :
                                risk.violationProbability > 0.4 ? 'warning' : 'success'
                              }
                            />
                          </Box>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            {risk.requirementName}
                          </Typography>
                          <LinearProgress
                            variant="determinate"
                            value={risk.violationProbability * 100}
                            sx={{ height: 6, borderRadius: 3 }}
                            color={
                              risk.violationProbability > 0.7 ? 'error' :
                              risk.violationProbability > 0.4 ? 'warning' : 'success'
                            }
                          />
                          {risk.potentialFines && (
                            <Typography variant="caption" color="error" sx={{ mt: 1, display: 'block' }}>
                              Potential fines: {formatCurrency(risk.potentialFines.minImpact)} - {formatCurrency(risk.potentialFines.maxImpact)}
                            </Typography>
                          )}
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
          </Grid>
        )}
      </Grid>

      {/* Detail Dialog */}
      <Dialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="md"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {selectedDetail?.type === 'threat' && <WarningIcon color="error" />}
            {selectedDetail?.type === 'recommendation' && <TaskIcon color="primary" />}
            {selectedDetail?.type === 'investment' && <InvestmentIcon color="success" />}
            {selectedDetail?.type === 'compliance' && <ComplianceIcon color="info" />}
            <Typography variant="h6">
              {selectedDetail?.title || selectedDetail?.threatType || selectedDetail?.framework || 'Details'}
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedDetail && (
            <Box sx={{ mt: 1 }}>
              {selectedDetail.type === 'recommendation' && (
                <Box>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Description:</strong> {selectedDetail.description}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Business Justification:</strong> {selectedDetail.businessJustification}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Expected Outcome:</strong> {selectedDetail.expectedOutcome}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Implementation Time:</strong> {formatDuration(selectedDetail.implementationTime)}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Responsible Party:</strong> {selectedDetail.responsibleParty}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Chip label={selectedDetail.priority} color={selectedDetail.priority === 'CRITICAL' ? 'error' : 'default'} />
                    <Chip label={`${Math.round(selectedDetail.riskReduction * 100)}% Risk Reduction`} color="success" />
                    <Chip label={`${Math.round(selectedDetail.confidenceScore * 100)}% Confidence`} variant="outlined" />
                    {selectedDetail.executiveApprovalRequired && (
                      <Chip label="Executive Approval Required" color="warning" />
                    )}
                  </Box>
                </Box>
              )}
              
              {selectedDetail.type === 'investment' && (
                <Box>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Business Case:</strong> {selectedDetail.businessCase}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Initial Investment:</strong> {formatCurrency(selectedDetail.estimatedCost.initialCost, selectedDetail.estimatedCost.currency)}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Expected ROI:</strong> {Math.round(selectedDetail.expectedROI * 100)}% over {formatDuration(selectedDetail.roiTimeframe)}
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    <strong>Risk Reduction:</strong> {Math.round(selectedDetail.riskReduction * 100)}%
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Chip label={`${Math.round(selectedDetail.confidenceLevel * 100)}% Confidence`} color="info" />
                    {selectedDetail.executiveSponsorshipRequired && (
                      <Chip label="Executive Sponsor Required" color="primary" />
                    )}
                    {selectedDetail.boardApprovalRequired && (
                      <Chip label="Board Approval Required" color="warning" />
                    )}
                  </Box>
                </Box>
              )}
              
              {/* Add other detail types as needed */}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(false)}>
            Close
          </Button>
          {selectedDetail?.type === 'recommendation' && onRecommendationClick && (
            <Button 
              variant="contained" 
              onClick={() => {
                onRecommendationClick(selectedDetail.id);
                setDetailDialogOpen(false);
              }}
            >
              Take Action
            </Button>
          )}
          {selectedDetail?.type === 'investment' && onInvestmentClick && (
            <Button 
              variant="contained" 
              onClick={() => {
                onInvestmentClick(selectedDetail.id);
                setDetailDialogOpen(false);
              }}
            >
              Review Investment
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ExecutivePredictiveAnalytics;