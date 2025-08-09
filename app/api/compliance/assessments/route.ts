/**
 * Compliance Assessments API Route
 * Manages compliance assessments and their results
 */

import { NextRequest, NextResponse } from 'next/server';
import { ComplianceFramework, ComplianceStatus } from '../../../types/compliance';

// Mock assessments data generator
const generateMockAssessments = (limit: number = 10) => {
  const frameworks = [
    ComplianceFramework.GDPR,
    ComplianceFramework.HIPAA,
    ComplianceFramework.PCI_DSS,
    ComplianceFramework.SOC2,
    ComplianceFramework.ISO27001
  ];

  const assessors = [
    'compliance-team@isectech.com',
    'external-auditor@compliance-firm.com',
    'security-lead@isectech.com',
    'privacy-officer@isectech.com'
  ];

  const assessments = [];

  for (let i = 0; i < limit; i++) {
    const framework = frameworks[Math.floor(Math.random() * frameworks.length)];
    const timestamp = new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000); // Last 90 days
    const baseScore = 75 + Math.random() * 25; // 75-100%
    const score = Math.round(baseScore);
    
    // Generate realistic control numbers based on framework
    let totalControls = 20;
    switch (framework) {
      case ComplianceFramework.GDPR:
        totalControls = 25;
        break;
      case ComplianceFramework.HIPAA:
        totalControls = 18;
        break;
      case ComplianceFramework.PCI_DSS:
        totalControls = 22;
        break;
      case ComplianceFramework.SOC2:
        totalControls = 15;
        break;
      case ComplianceFramework.ISO27001:
        totalControls = 30;
        break;
    }

    const compliantControls = Math.floor((score / 100) * totalControls);
    const status = score >= 85 ? 'passed' : score >= 70 ? 'partial' : 'failed';
    
    // Generate findings based on compliance level
    const numFindings = Math.max(0, Math.floor((100 - score) / 10));
    const findings = [];
    
    const findingTemplates = [
      {
        severity: 'high' as const,
        description: `${framework.toUpperCase()} control implementation gaps identified in AI/ML data processing`,
        recommendation: 'Implement comprehensive data governance framework for AI systems'
      },
      {
        severity: 'medium' as const,
        description: 'Audit trail completeness needs improvement for sensitive data access',
        recommendation: 'Enhance logging mechanisms and implement automated log analysis'
      },
      {
        severity: 'medium' as const,
        description: 'Access control policies require updates for AI model management',
        recommendation: 'Review and update role-based access controls for ML operations'
      },
      {
        severity: 'low' as const,
        description: 'Documentation updates needed for compliance procedures',
        recommendation: 'Update compliance documentation to reflect current processes'
      },
      {
        severity: 'high' as const,
        description: 'Encryption standards not fully implemented across AI infrastructure',
        recommendation: 'Deploy enterprise encryption solution for all sensitive data'
      }
    ];

    for (let j = 0; j < numFindings; j++) {
      const template = findingTemplates[Math.floor(Math.random() * findingTemplates.length)];
      findings.push({
        ...template,
        id: `FINDING_${Date.now()}_${j}`,
        assessmentId: `ASSESS_${Date.now()}_${i}`
      });
    }

    assessments.push({
      id: `ASSESS_${Date.now()}_${i}`,
      framework,
      timestamp: timestamp.toISOString(),
      score,
      status,
      assessorId: assessors[Math.floor(Math.random() * assessors.length)],
      controlsAssessed: totalControls,
      compliantControls,
      findings,
      nextAssessmentDue: new Date(timestamp.getTime() + (framework === ComplianceFramework.SOC2 ? 365 : 180) * 24 * 60 * 60 * 1000).toISOString(),
      assessmentType: Math.random() < 0.7 ? 'internal' : 'external',
      duration: Math.floor(Math.random() * 40) + 10, // 10-50 hours
      methodology: ['Control Testing', 'Documentation Review', 'Interview', 'System Analysis'],
      scope: 'AI/ML Systems and Executive Analytics Platform',
      executiveSummary: `${framework.toUpperCase()} assessment completed with ${score}% compliance score. ${numFindings} findings identified requiring attention.`,
      keyStrengths: [
        'Strong data encryption implementation',
        'Comprehensive audit logging system',
        'Well-defined access control policies',
        'Regular security training programs'
      ].slice(0, Math.floor(Math.random() * 3) + 1),
      improvementAreas: findings.length > 0 ? findings.slice(0, 3).map(f => f.description) : [
        'Continue monitoring and maintenance of current controls'
      ]
    });
  }

  return assessments.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
};

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const framework = searchParams.get('framework');
    const status = searchParams.get('status');
    const assessorId = searchParams.get('assessorId');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');

    let assessments = generateMockAssessments(50); // Generate larger set for filtering

    // Apply filters
    if (framework) {
      assessments = assessments.filter(a => a.framework === framework);
    }

    if (status) {
      assessments = assessments.filter(a => a.status === status);
    }

    if (assessorId) {
      assessments = assessments.filter(a => a.assessorId === assessorId);
    }

    if (startDate) {
      const start = new Date(startDate);
      assessments = assessments.filter(a => new Date(a.timestamp) >= start);
    }

    if (endDate) {
      const end = new Date(endDate);
      assessments = assessments.filter(a => new Date(a.timestamp) <= end);
    }

    // Apply pagination
    const total = assessments.length;
    const totalPages = Math.ceil(total / limit);
    const startIndex = (page - 1) * limit;
    const paginatedAssessments = assessments.slice(startIndex, startIndex + limit);

    // Calculate statistics
    const stats = {
      total,
      passed: assessments.filter(a => a.status === 'passed').length,
      partial: assessments.filter(a => a.status === 'partial').length,
      failed: assessments.filter(a => a.status === 'failed').length,
      averageScore: Math.round(assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length),
      totalFindings: assessments.reduce((sum, a) => sum + a.findings.length, 0),
      criticalFindings: assessments.reduce((sum, a) => sum + a.findings.filter(f => f.severity === 'high').length, 0),
      frameworkDistribution: Object.values(ComplianceFramework).reduce((acc, fw) => {
        acc[fw] = assessments.filter(a => a.framework === fw).length;
        return acc;
      }, {} as Record<string, number>),
      assessmentTrend: 'stable' // Would be calculated based on historical data
    };

    // Upcoming assessments (next 30 days)
    const upcomingAssessments = assessments.filter(a => {
      const dueDate = new Date(a.nextAssessmentDue);
      const thirtyDaysFromNow = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      return dueDate <= thirtyDaysFromNow;
    }).map(a => ({
      id: a.id,
      framework: a.framework,
      dueDate: a.nextAssessmentDue,
      lastScore: a.score,
      assessor: a.assessorId
    }));

    const response = {
      success: true,
      data: {
        assessments: paginatedAssessments,
        statistics: stats,
        upcomingAssessments,
        filters: {
          frameworks: Object.values(ComplianceFramework),
          statuses: ['passed', 'partial', 'failed'],
          assessmentTypes: ['internal', 'external', 'self-assessment'],
          severities: ['critical', 'high', 'medium', 'low']
        }
      },
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      },
      timestamp: new Date().toISOString()
    };

    return NextResponse.json(response);

  } catch (error) {
    console.error('Error fetching assessments:', error);
    
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error',
        message: 'Failed to fetch assessments',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, ...parameters } = body;

    switch (action) {
      case 'schedule':
        const { framework, scheduledDate, assessorId, type } = parameters;
        
        // Validate required parameters
        if (!framework || !scheduledDate) {
          return NextResponse.json(
            {
              success: false,
              error: 'Missing required parameters',
              message: 'Framework and scheduledDate are required'
            },
            { status: 400 }
          );
        }

        const assessmentId = `ASSESS_${Date.now()}`;
        
        return NextResponse.json({
          success: true,
          message: `Assessment scheduled for ${framework}`,
          data: {
            assessmentId,
            framework,
            scheduledDate,
            assessorId: assessorId || 'compliance-team@isectech.com',
            type: type || 'comprehensive',
            estimatedDuration: '2-3 weeks',
            preparationItems: [
              'Gather compliance documentation',
              'Prepare system access for assessor',
              'Schedule stakeholder interviews',
              'Review previous assessment findings'
            ]
          },
          timestamp: new Date().toISOString()
        });

      case 'initiate':
        const { assessmentPlan } = parameters;
        
        return NextResponse.json({
          success: true,
          message: 'Assessment initiated',
          data: {
            assessmentId: `ASSESS_${Date.now()}`,
            status: 'in_progress',
            startedAt: new Date().toISOString(),
            estimatedCompletion: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000).toISOString(), // 3 weeks
            currentPhase: 'planning',
            nextMilestone: 'Documentation Review',
            progressPercentage: 5
          },
          timestamp: new Date().toISOString()
        });

      case 'submit_evidence':
        const { assessmentId, evidenceType, files } = parameters;
        
        return NextResponse.json({
          success: true,
          message: 'Evidence submitted successfully',
          data: {
            assessmentId,
            evidenceId: `EVIDENCE_${Date.now()}`,
            evidenceType,
            filesProcessed: files?.length || 1,
            submittedAt: new Date().toISOString(),
            reviewStatus: 'pending'
          },
          timestamp: new Date().toISOString()
        });

      case 'update_progress':
        const { assessmentId: updateId, phase, percentage } = parameters;
        
        return NextResponse.json({
          success: true,
          message: 'Assessment progress updated',
          data: {
            assessmentId: updateId,
            currentPhase: phase,
            progressPercentage: percentage,
            updatedAt: new Date().toISOString(),
            nextMilestone: 'Control Testing'
          },
          timestamp: new Date().toISOString()
        });

      default:
        return NextResponse.json(
          {
            success: false,
            error: 'Invalid action',
            validActions: ['schedule', 'initiate', 'submit_evidence', 'update_progress']
          },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('Error processing assessment action:', error);
    
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error',
        message: 'Failed to process assessment action',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}