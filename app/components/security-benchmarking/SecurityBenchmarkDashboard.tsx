import React, { useState, useEffect, useMemo } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  Shield,
  AlertTriangle,
  Target,
  Award,
  BarChart3,
  Activity,
  Users,
  Zap,
  Clock,
  CheckCircle,
  XCircle,
  ArrowUp,
  ArrowDown,
  Minus,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

// Types
interface SecurityScore {
  id: string;
  tenant_id: string;
  organization_id: string;
  overall_score: number;
  threat_blocking_score: number;
  incident_impact_score: number;
  response_efficiency: number;
  prevention_effectiveness: number;
  component_scores: Record<string, number>;
  trend_direction: 'improving' | 'declining' | 'stable' | 'volatile';
  change_percent: number;
  predicted_score?: number;
  target_score: number;
  is_target_achievable: boolean;
  security_clearance: string;
  confidence_level: number;
  calculation_timestamp: string;
}

interface IndustryBenchmark {
  id: string;
  industry: string;
  company_size: string;
  geographic_region: string;
  average_score: number;
  median_score: number;
  best_in_class_score: number;
  percentile_25: number;
  percentile_50: number;
  percentile_75: number;
  percentile_90: number;
  percentile_95: number;
  sample_size: number;
  confidence_level: number;
  last_updated: string;
}

interface PeerComparison {
  id: string;
  organization_score: number;
  peer_average_score: number;
  peer_median_score: number;
  industry_ranking: number;
  peer_ranking: number;
  percentile_ranking: number;
  score_gap: number;
  component_gaps: Record<string, number>;
  improvement_areas: ImprovementArea[];
  quick_wins: QuickWin[];
  peer_count: number;
}

interface ImprovementArea {
  area: string;
  current_score: number;
  peer_average_score: number;
  best_in_class_score: number;
  improvement_potential: number;
  priority: 'low' | 'medium' | 'high' | 'critical';
  estimated_cost: 'low' | 'medium' | 'high' | 'very_high';
  estimated_timeframe: number; // in days
  expected_roi: number;
  recommendations: string[];
}

interface QuickWin {
  name: string;
  description: string;
  expected_improvement: number;
  implementation_time: number; // in days
  required_resources: string[];
  estimated_cost: 'low' | 'medium' | 'high' | 'very_high';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  success_probability: number;
}

interface MaturityAssessment {
  id: string;
  overall_maturity_level: 'initial' | 'managed' | 'defined' | 'quantified' | 'optimized';
  maturity_score: number;
  industry_benchmark: number;
  peer_comparison: number;
  best_practice_gap: number;
  next_maturity_level: string;
  time_to_next_level: number; // in days
  domain_maturity: Record<string, {
    domain: string;
    maturity_level: string;
    score: number;
    strengths: string[];
    weaknesses: string[];
  }>;
}

interface DashboardData {
  current_score: SecurityScore;
  industry_benchmark: IndustryBenchmark;
  peer_comparison: PeerComparison;
  maturity_assessment: MaturityAssessment;
  score_history: Array<{
    timestamp: string;
    historical_score: number;
    change_from_previous: number;
  }>;
  key_metrics: {
    threat_blocking_rate: number;
    incident_response_time: number;
    vulnerability_patch_time: number;
    compliance_score: number;
    security_investment: number;
    roi_security_investment: number;
    risk_reduction: number;
    team_efficiency: number;
  };
  trends: Array<{
    timestamp: string;
    metric: string;
    value: number;
    change: number;
    change_percent: number;
    category: string;
    significance: 'significant' | 'moderate' | 'minor';
  }>;
  risk_factors: Array<{
    name: string;
    category: string;
    impact: number;
    probability: number;
    description: string;
  }>;
  compliance_status: Record<string, number>;
  recommendations: Array<{
    id: string;
    title: string;
    priority: string;
    category: string;
    expected_impact: number;
    estimated_cost: string;
    timeline: number;
    status: string;
    description: string;
  }>;
}

interface SecurityBenchmarkDashboardProps {
  tenantId: string;
  organizationId: string;
  onExportReport?: (format: 'pdf' | 'pptx' | 'xlsx' | 'json') => void;
  className?: string;
}

const SecurityBenchmarkDashboard: React.FC<SecurityBenchmarkDashboardProps> = ({
  tenantId,
  organizationId,
  onExportReport,
  className,
}) => {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTimeframe, setSelectedTimeframe] = useState<'7d' | '30d' | '90d' | '1y'>('30d');

  // Load dashboard data
  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        setIsLoading(true);
        const response = await fetch(`/api/security-benchmarking/dashboard/${tenantId}/${organizationId}?timeframe=${selectedTimeframe}`);
        if (!response.ok) {
          throw new Error('Failed to load dashboard data');
        }
        const data = await response.json();
        setDashboardData(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error occurred');
      } finally {
        setIsLoading(false);
      }
    };

    loadDashboardData();
  }, [tenantId, organizationId, selectedTimeframe]);

  // Color schemes for charts
  const scoreColors = {
    excellent: '#10B981', // green-500
    good: '#3B82F6',      // blue-500
    average: '#F59E0B',   // amber-500
    poor: '#EF4444',      // red-500
  };

  const getScoreColor = (score: number): string => {
    if (score >= 90) return scoreColors.excellent;
    if (score >= 80) return scoreColors.good;
    if (score >= 70) return scoreColors.average;
    return scoreColors.poor;
  };

  const getScoreGrade = (score: number): string => {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  };

  const getRiskLevel = (score: number): { level: string; color: string } => {
    if (score >= 80) return { level: 'Low', color: 'text-green-600' };
    if (score >= 60) return { level: 'Medium', color: 'text-yellow-600' };
    if (score >= 40) return { level: 'High', color: 'text-orange-600' };
    return { level: 'Critical', color: 'text-red-600' };
  };

  const getTrendIcon = (direction: string, changePercent: number) => {
    const absChange = Math.abs(changePercent);
    if (direction === 'improving') {
      return <ArrowUp className="h-4 w-4 text-green-600" />;
    } else if (direction === 'declining') {
      return <ArrowDown className="h-4 w-4 text-red-600" />;
    } else if (direction === 'volatile') {
      return <Activity className="h-4 w-4 text-orange-600" />;
    }
    return <Minus className="h-4 w-4 text-gray-600" />;
  };

  const formatDuration = (days: number): string => {
    if (days < 7) return `${days} days`;
    if (days < 30) return `${Math.round(days / 7)} weeks`;
    if (days < 365) return `${Math.round(days / 30)} months`;
    return `${Math.round(days / 365)} years`;
  };

  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      notation: 'compact',
    }).format(amount);
  };

  // Prepare chart data
  const scoreHistoryData = useMemo(() => {
    if (!dashboardData?.score_history) return [];
    return dashboardData.score_history.map(item => ({
      date: new Date(item.timestamp).toLocaleDateString(),
      score: item.historical_score,
      change: item.change_from_previous,
    }));
  }, [dashboardData?.score_history]);

  const componentScoresData = useMemo(() => {
    if (!dashboardData?.current_score?.component_scores) return [];
    return Object.entries(dashboardData.current_score.component_scores).map(([component, score]) => ({
      component: component.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      score,
      benchmark: dashboardData.industry_benchmark?.average_score || 75,
      gap: dashboardData.peer_comparison?.component_gaps?.[component] || 0,
    }));
  }, [dashboardData?.current_score?.component_scores, dashboardData?.industry_benchmark, dashboardData?.peer_comparison]);

  const maturityRadarData = useMemo(() => {
    if (!dashboardData?.maturity_assessment?.domain_maturity) return [];
    return Object.values(dashboardData.maturity_assessment.domain_maturity).map(domain => ({
      domain: domain.domain.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      current: domain.score,
      target: Math.min(domain.score + 20, 100),
      industry: dashboardData.maturity_assessment.industry_benchmark,
    }));
  }, [dashboardData?.maturity_assessment]);

  const riskFactorsData = useMemo(() => {
    if (!dashboardData?.risk_factors) return [];
    return dashboardData.risk_factors.map(risk => ({
      name: risk.name,
      impact: Math.abs(risk.impact),
      probability: risk.probability * 100,
      risk_score: Math.abs(risk.impact) * risk.probability,
      category: risk.category,
    }));
  }, [dashboardData?.risk_factors]);

  if (isLoading) {
    return (
      <div className={`p-6 space-y-6 ${className}`}>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`p-6 ${className}`}>
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error Loading Dashboard</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (!dashboardData) return null;

  const { current_score, industry_benchmark, peer_comparison, maturity_assessment } = dashboardData;
  const riskLevel = getRiskLevel(current_score.overall_score);

  return (
    <div className={`p-6 space-y-6 ${className}`}>
      {/* Header with Key Metrics */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Benchmark Dashboard</h1>
          <p className="text-gray-600 mt-1">Comprehensive security effectiveness analysis and industry comparison</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedTimeframe}
            onChange={(e) => setSelectedTimeframe(e.target.value as any)}
            className="px-3 py-2 border border-gray-300 rounded-md text-sm"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </select>
          {onExportReport && (
            <div className="flex gap-1">
              <button
                onClick={() => onExportReport('pdf')}
                className="px-3 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700"
              >
                Export PDF
              </button>
              <button
                onClick={() => onExportReport('pptx')}
                className="px-3 py-2 bg-green-600 text-white rounded-md text-sm hover:bg-green-700"
              >
                Export PPT
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Executive Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Overall Security Score</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" style={{ color: getScoreColor(current_score.overall_score) }}>
              {current_score.overall_score.toFixed(1)}
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant={current_score.overall_score >= 80 ? 'default' : 'destructive'}>
                Grade {getScoreGrade(current_score.overall_score)}
              </Badge>
              {getTrendIcon(current_score.trend_direction, current_score.change_percent)}
              <p className="text-xs text-muted-foreground">
                {current_score.change_percent > 0 ? '+' : ''}{current_score.change_percent.toFixed(1)}%
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Industry Ranking</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {peer_comparison.percentile_ranking.toFixed(0)}th
            </div>
            <p className="text-xs text-muted-foreground">
              Percentile ({peer_comparison.peer_count} peers)
            </p>
            <div className="mt-2">
              <Badge variant={peer_comparison.percentile_ranking >= 75 ? 'default' : 'secondary'}>
                {peer_comparison.percentile_ranking >= 90 ? 'Top Performer' :
                 peer_comparison.percentile_ranking >= 75 ? 'Above Average' :
                 peer_comparison.percentile_ranking >= 50 ? 'Average' :
                 peer_comparison.percentile_ranking >= 25 ? 'Below Average' : 'Needs Improvement'}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${riskLevel.color}`}>
              {riskLevel.level}
            </div>
            <p className="text-xs text-muted-foreground">
              Based on current score and threats
            </p>
            <div className="mt-2">
              <Progress 
                value={current_score.overall_score} 
                className="h-2"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Maturity Level</CardTitle>
            <Award className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">
              {maturity_assessment.overall_maturity_level}
            </div>
            <p className="text-xs text-muted-foreground">
              Score: {maturity_assessment.maturity_score.toFixed(1)}/100
            </p>
            <div className="mt-2">
              <Badge variant="outline">
                Next: {maturity_assessment.next_maturity_level}
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Dashboard Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="benchmarking">Benchmarking</TabsTrigger>
          <TabsTrigger value="maturity">Maturity</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
          <TabsTrigger value="recommendations">Actions</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Score History Chart */}
            <Card>
              <CardHeader>
                <CardTitle>Security Score Trend</CardTitle>
                <CardDescription>Historical performance over selected timeframe</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={scoreHistoryData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip />
                    <Line 
                      type="monotone" 
                      dataKey="score" 
                      stroke="#3B82F6" 
                      strokeWidth={2}
                      dot={{ fill: '#3B82F6', strokeWidth: 2, r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Component Scores Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle>Component Performance</CardTitle>
                <CardDescription>Security component effectiveness scores</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={componentScoresData} layout="horizontal">
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" domain={[0, 100]} />
                    <YAxis dataKey="component" type="category" width={120} />
                    <Tooltip />
                    <Bar dataKey="score" fill="#3B82F6" />
                    <Bar dataKey="benchmark" fill="#E5E7EB" opacity={0.5} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Threat Blocking Rate</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {(dashboardData.key_metrics.threat_blocking_rate * 100).toFixed(1)}%
                </div>
                <Progress value={dashboardData.key_metrics.threat_blocking_rate * 100} className="mt-2" />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Incident Response Time</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {Math.round(dashboardData.key_metrics.incident_response_time / 3600)}h
                </div>
                <p className="text-xs text-muted-foreground mt-1">Average response time</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Security ROI</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  {dashboardData.key_metrics.roi_security_investment.toFixed(1)}x
                </div>
                <p className="text-xs text-muted-foreground mt-1">Return on investment</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Risk Reduction</CardTitle>
                <Target className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  {(dashboardData.key_metrics.risk_reduction * 100).toFixed(0)}%
                </div>
                <p className="text-xs text-muted-foreground mt-1">Overall risk reduction</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Benchmarking Tab */}
        <TabsContent value="benchmarking" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Industry Comparison */}
            <Card>
              <CardHeader>
                <CardTitle>Industry Benchmark Comparison</CardTitle>
                <CardDescription>
                  {industry_benchmark.industry} • {industry_benchmark.company_size} • {industry_benchmark.geographic_region}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Your Score</span>
                    <span className="text-lg font-bold" style={{ color: getScoreColor(current_score.overall_score) }}>
                      {current_score.overall_score.toFixed(1)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">Industry Average</span>
                    <span className="text-lg">{industry_benchmark.average_score.toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">Best in Class</span>
                    <span className="text-lg text-green-600">{industry_benchmark.best_in_class_score.toFixed(1)}</span>
                  </div>
                  <div className="mt-4">
                    <div className="text-sm text-gray-600 mb-2">Industry Distribution</div>
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs">
                        <span>25th</span>
                        <span>50th</span>
                        <span>75th</span>
                        <span>90th</span>
                      </div>
                      <div className="relative h-2 bg-gray-200 rounded-full">
                        <div 
                          className="absolute h-full bg-blue-500 rounded-full"
                          style={{ width: `${(current_score.overall_score / 100) * 100}%` }}
                        />
                        <div className="absolute inset-0 flex justify-between">
                          <div className="w-px h-full bg-gray-400" style={{ left: `${industry_benchmark.percentile_25}%` }} />
                          <div className="w-px h-full bg-gray-400" style={{ left: `${industry_benchmark.percentile_50}%` }} />
                          <div className="w-px h-full bg-gray-400" style={{ left: `${industry_benchmark.percentile_75}%` }} />
                          <div className="w-px h-full bg-gray-400" style={{ left: `${industry_benchmark.percentile_90}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Peer Analysis */}
            <Card>
              <CardHeader>
                <CardTitle>Peer Group Analysis</CardTitle>
                <CardDescription>Comparison with {peer_comparison.peer_count} similar organizations</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-blue-600 mb-2">
                      #{peer_comparison.peer_ranking}
                    </div>
                    <div className="text-sm text-gray-600">
                      Ranking among peers
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-lg font-semibold">{peer_comparison.peer_average_score.toFixed(1)}</div>
                      <div className="text-xs text-gray-600">Peer Average</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className={`text-lg font-semibold ${peer_comparison.score_gap >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                        {peer_comparison.score_gap >= 0 ? '+' : ''}{peer_comparison.score_gap.toFixed(1)}
                      </div>
                      <div className="text-xs text-gray-600">Gap to Average</div>
                    </div>
                  </div>

                  <div className="text-center">
                    <Badge 
                      variant={peer_comparison.percentile_ranking >= 75 ? 'default' : 'secondary'}
                      className="text-sm"
                    >
                      {peer_comparison.percentile_ranking.toFixed(0)}th Percentile
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Component Gap Analysis */}
          <Card>
            <CardHeader>
              <CardTitle>Component Gap Analysis</CardTitle>
              <CardDescription>Performance gaps compared to peer averages by security component</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={componentScoresData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="component" angle={-45} textAnchor="end" height={100} />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="score" name="Your Score" fill="#3B82F6" />
                  <Bar dataKey="benchmark" name="Peer Average" fill="#10B981" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Maturity Tab */}
        <TabsContent value="maturity" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Maturity Radar Chart */}
            <Card>
              <CardHeader>
                <CardTitle>Security Maturity Radar</CardTitle>
                <CardDescription>Maturity assessment across security domains</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={400}>
                  <RadarChart data={maturityRadarData}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="domain" />
                    <PolarRadiusAxis domain={[0, 100]} />
                    <Radar name="Current" dataKey="current" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
                    <Radar name="Target" dataKey="target" stroke="#10B981" fill="#10B981" fillOpacity={0.1} />
                    <Radar name="Industry" dataKey="industry" stroke="#F59E0B" fill="none" strokeDasharray="5 5" />
                    <Legend />
                  </RadarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Maturity Progress */}
            <Card>
              <CardHeader>
                <CardTitle>Maturity Progression</CardTitle>
                <CardDescription>Path to next maturity level</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="text-center">
                    <div className="text-2xl font-bold capitalize mb-2">
                      {maturity_assessment.overall_maturity_level}
                    </div>
                    <div className="text-sm text-gray-600">Current Level</div>
                    <div className="mt-4">
                      <Progress value={maturity_assessment.maturity_score} className="h-3" />
                      <div className="flex justify-between text-xs text-gray-500 mt-1">
                        <span>0</span>
                        <span>{maturity_assessment.maturity_score.toFixed(0)}</span>
                        <span>100</span>
                      </div>
                    </div>
                  </div>

                  <div className="border-t pt-4">
                    <div className="flex items-center justify-between mb-4">
                      <span className="font-medium">Next Level:</span>
                      <Badge variant="outline" className="capitalize">
                        {maturity_assessment.next_maturity_level}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-gray-600">Estimated Time:</span>
                      <span className="text-sm font-medium">
                        {formatDuration(maturity_assessment.time_to_next_level)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Gap to Best Practice:</span>
                      <span className="text-sm font-medium">
                        {maturity_assessment.best_practice_gap.toFixed(1)} points
                      </span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Domain Details */}
          <Card>
            <CardHeader>
              <CardTitle>Domain Analysis</CardTitle>
              <CardDescription>Detailed breakdown by security domain</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.values(maturity_assessment.domain_maturity).map((domain, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium capitalize">{domain.domain.replace(/_/g, ' ')}</h4>
                      <div className="flex items-center space-x-2">
                        <Badge variant="outline" className="capitalize">
                          {domain.maturity_level}
                        </Badge>
                        <span className="font-semibold">{domain.score.toFixed(0)}/100</span>
                      </div>
                    </div>
                    <Progress value={domain.score} className="mb-3" />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <h5 className="font-medium text-green-700 mb-2 flex items-center">
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Strengths
                        </h5>
                        <ul className="space-y-1">
                          {domain.strengths.map((strength, i) => (
                            <li key={i} className="text-gray-600">• {strength}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <h5 className="font-medium text-red-700 mb-2 flex items-center">
                          <XCircle className="h-4 w-4 mr-1" />
                          Areas for Improvement
                        </h5>
                        <ul className="space-y-1">
                          {domain.weaknesses.map((weakness, i) => (
                            <li key={i} className="text-gray-600">• {weakness}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Trends Tab */}
        <TabsContent value="trends" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Trend Analysis */}
            <Card>
              <CardHeader>
                <CardTitle>Security Trends</CardTitle>
                <CardDescription>Key security metrics trends over time</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {dashboardData.trends.map((trend, index) => (
                    <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 rounded-full bg-blue-100">
                          <Activity className="h-4 w-4 text-blue-600" />
                        </div>
                        <div>
                          <div className="font-medium">{trend.metric}</div>
                          <div className="text-sm text-gray-600">
                            {new Date(trend.timestamp).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="font-semibold">{trend.value.toFixed(1)}</div>
                        <div className={`text-sm flex items-center ${
                          trend.change > 0 ? 'text-green-600' : trend.change < 0 ? 'text-red-600' : 'text-gray-600'
                        }`}>
                          {trend.change > 0 ? <ArrowUp className="h-3 w-3 mr-1" /> : 
                           trend.change < 0 ? <ArrowDown className="h-3 w-3 mr-1" /> :
                           <Minus className="h-3 w-3 mr-1" />}
                          {Math.abs(trend.change_percent).toFixed(1)}%
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Risk Factors Heatmap */}
            <Card>
              <CardHeader>
                <CardTitle>Risk Factor Analysis</CardTitle>
                <CardDescription>Current risk factors by impact and probability</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={riskFactorsData}
                      dataKey="risk_score"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label={({ name, risk_score }) => `${name}: ${risk_score.toFixed(1)}`}
                    >
                      {riskFactorsData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={['#EF4444', '#F59E0B', '#10B981', '#3B82F6'][index % 4]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Predictive Analysis */}
          {current_score.predicted_score && (
            <Card>
              <CardHeader>
                <CardTitle>Predictive Analysis</CardTitle>
                <CardDescription>Forecasted security score based on current trends</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {current_score.predicted_score.toFixed(1)}
                    </div>
                    <div className="text-sm text-gray-600">Predicted Score</div>
                    <div className="text-xs text-gray-500 mt-1">30-day forecast</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold">
                      {current_score.confidence_level.toFixed(0)}%
                    </div>
                    <div className="text-sm text-gray-600">Confidence Level</div>
                    <div className="text-xs text-gray-500 mt-1">Prediction accuracy</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold ${
                      current_score.predicted_score >= current_score.target_score ? 'text-green-600' : 'text-orange-600'
                    }`}>
                      {current_score.is_target_achievable ? 'Yes' : 'Unlikely'}
                    </div>
                    <div className="text-sm text-gray-600">Target Achievable</div>
                    <div className="text-xs text-gray-500 mt-1">
                      Target: {current_score.target_score.toFixed(1)}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Recommendations Tab */}
        <TabsContent value="recommendations" className="space-y-6">
          {/* Quick Wins */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="h-5 w-5 mr-2 text-yellow-500" />
                Quick Wins
              </CardTitle>
              <CardDescription>High-impact, low-effort improvements you can implement immediately</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {peer_comparison.quick_wins.map((win, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <h4 className="font-medium mb-1">{win.name}</h4>
                        <p className="text-sm text-gray-600 mb-2">{win.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Impact: +{win.expected_improvement.toFixed(1)} points</span>
                          <span>Time: {formatDuration(win.implementation_time)}</span>
                          <span>Success: {(win.success_probability * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                      <div className="flex flex-col items-end space-y-1">
                        <Badge variant={win.risk_level === 'low' ? 'default' : 'secondary'}>
                          {win.risk_level} risk
                        </Badge>
                        <Badge variant="outline" className="capitalize">
                          {win.estimated_cost} cost
                        </Badge>
                      </div>
                    </div>
                    <div className="border-t pt-3">
                      <div className="text-xs text-gray-600 mb-2">Required Resources:</div>
                      <div className="flex flex-wrap gap-1">
                        {win.required_resources.map((resource, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {resource}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Improvement Areas */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Target className="h-5 w-5 mr-2 text-blue-500" />
                Priority Improvement Areas
              </CardTitle>
              <CardDescription>Focused improvements based on peer comparison analysis</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {peer_comparison.improvement_areas
                  .sort((a, b) => {
                    const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
                    return priorityOrder[b.priority] - priorityOrder[a.priority];
                  })
                  .map((area, index) => (
                    <div key={index} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <h4 className="font-medium">{area.area}</h4>
                            <Badge variant={area.priority === 'critical' ? 'destructive' : 
                                           area.priority === 'high' ? 'default' : 'secondary'}>
                              {area.priority}
                            </Badge>
                          </div>
                          <div className="grid grid-cols-3 gap-4 text-sm mb-3">
                            <div>
                              <div className="text-gray-600">Current Score</div>
                              <div className="font-semibold">{area.current_score.toFixed(1)}</div>
                            </div>
                            <div>
                              <div className="text-gray-600">Peer Average</div>
                              <div className="font-semibold">{area.peer_average_score.toFixed(1)}</div>
                            </div>
                            <div>
                              <div className="text-gray-600">Best in Class</div>
                              <div className="font-semibold text-green-600">{area.best_in_class_score.toFixed(1)}</div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>Potential: +{area.improvement_potential.toFixed(1)} points</span>
                            <span>Timeline: {formatDuration(area.estimated_timeframe)}</span>
                            <span>ROI: {area.expected_roi.toFixed(1)}x</span>
                          </div>
                        </div>
                        <Badge variant="outline" className="capitalize">
                          {area.estimated_cost} cost
                        </Badge>
                      </div>
                      <div className="border-t pt-3">
                        <div className="text-xs text-gray-600 mb-2">Recommendations:</div>
                        <ul className="text-sm space-y-1">
                          {area.recommendations.map((rec, i) => (
                            <li key={i} className="text-gray-700">• {rec}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>

          {/* All Recommendations */}
          <Card>
            <CardHeader>
              <CardTitle>All Recommendations</CardTitle>
              <CardDescription>Complete list of improvement recommendations</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {dashboardData.recommendations.map((rec) => (
                  <div key={rec.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-1">
                        <h4 className="font-medium">{rec.title}</h4>
                        <Badge variant={rec.priority === 'Critical' ? 'destructive' : 
                                       rec.priority === 'High' ? 'default' : 'secondary'}>
                          {rec.priority}
                        </Badge>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">{rec.description}</p>
                      <div className="flex items-center space-x-4 text-xs text-gray-500">
                        <span>Impact: +{rec.expected_impact.toFixed(1)}</span>
                        <span>Timeline: {formatDuration(rec.timeline)}</span>
                        <span>Cost: {rec.estimated_cost}</span>
                      </div>
                    </div>
                    <Badge variant={rec.status === 'pending' ? 'secondary' : 'default'}>
                      {rec.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SecurityBenchmarkDashboard;