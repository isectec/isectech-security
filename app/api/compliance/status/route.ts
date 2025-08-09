/**
 * Compliance Status API Route
 * Provides executive compliance status and metrics
 */

import { NextRequest, NextResponse } from 'next/server';
import { ComplianceFramework, ComplianceStatus } from '../../../types/compliance';

// Mock data for demonstration - in production, this would connect to the compliance backend
const generateMockComplianceStatus = () => {
  const frameworks = [
    ComplianceFramework.GDPR,
    ComplianceFramework.HIPAA,
    ComplianceFramework.PCI_DSS,
    ComplianceFramework.SOC2,
    ComplianceFramework.ISO27001
  ];

  const frameworkStatus: Record<string, any> = {};

  frameworks.forEach(framework => {
    // Generate realistic compliance scores
    let baseScore = 85;
    let totalControls = 20;
    let criticalViolations = 0;
    let highViolations = 0;

    switch (framework) {
      case ComplianceFramework.GDPR:
        baseScore = 92;
        totalControls = 25;
        criticalViolations = 0;
        highViolations = 1;
        break;
      case ComplianceFramework.HIPAA:
        baseScore = 96;
        totalControls = 18;
        criticalViolations = 0;
        highViolations = 0;
        break;
      case ComplianceFramework.PCI_DSS:
        baseScore = 89;
        totalControls = 22;
        criticalViolations = 1;
        highViolations = 2;
        break;
      case ComplianceFramework.SOC2:
        baseScore = 94;
        totalControls = 15;
        criticalViolations = 0;
        highViolations = 1;
        break;
      case ComplianceFramework.ISO27001:
        baseScore = 87;
        totalControls = 30;
        criticalViolations = 0;
        highViolations = 3;
        break;
    }

    const compliantControls = Math.floor((baseScore / 100) * totalControls);
    
    frameworkStatus[framework] = {
      compliancePercentage: baseScore,
      totalControls,
      compliantControls,
      lastAssessment: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
      nextAssessmentDue: new Date(Date.now() + Math.random() * 90 * 24 * 60 * 60 * 1000).toISOString(),
      criticalViolations,
      highViolations,
      trend: criticalViolations > 0 ? 'declining' : highViolations > 2 ? 'stable' : 'improving'
    };
  });

  return frameworkStatus;
};

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const framework = searchParams.get('framework');
    const detailed = searchParams.get('detailed') === 'true';

    // Generate mock compliance status
    const frameworkStatus = generateMockComplianceStatus();

    // Filter by specific framework if requested
    const filteredStatus = framework && framework !== 'all' 
      ? { [framework]: frameworkStatus[framework] }
      : frameworkStatus;

    // Calculate overall metrics
    const frameworks = Object.keys(filteredStatus);
    const totalCompliance = frameworks.reduce((sum, fw) => 
      sum + filteredStatus[fw].compliancePercentage, 0
    ) / frameworks.length;

    const totalViolations = frameworks.reduce((sum, fw) => 
      sum + filteredStatus[fw].criticalViolations + filteredStatus[fw].highViolations, 0
    );

    const criticalViolations = frameworks.reduce((sum, fw) => 
      sum + filteredStatus[fw].criticalViolations, 0
    );

    // Risk level calculation
    let riskLevel = 'low';
    if (criticalViolations > 0) {
      riskLevel = 'critical';
    } else if (totalCompliance < 85) {
      riskLevel = 'high';
    } else if (totalCompliance < 95) {
      riskLevel = 'medium';
    }

    const response = {
      success: true,
      data: {
        frameworkStatus: filteredStatus,
        overallMetrics: {
          compliancePercentage: Math.round(totalCompliance),
          totalFrameworks: frameworks.length,
          totalViolations,
          criticalViolations,
          riskLevel,
          trend: criticalViolations > 0 ? 'declining' : 'stable'
        },
        lastUpdated: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    };

    if (detailed) {
      // Add detailed control information
      response.data.detailedControls = {};
      
      frameworks.forEach(fw => {
        const controls = [];
        const frameworkData = filteredStatus[fw];
        
        for (let i = 1; i <= frameworkData.totalControls; i++) {
          const isCompliant = i <= frameworkData.compliantControls;
          controls.push({
            id: `${fw.toUpperCase()}_${i.toString().padStart(2, '0')}`,
            name: `Control ${fw.toUpperCase()}-${i}`,
            status: isCompliant ? ComplianceStatus.COMPLIANT : ComplianceStatus.NON_COMPLIANT,
            lastAssessed: frameworkData.lastAssessment,
            riskLevel: isCompliant ? 'low' : i > frameworkData.totalControls - 2 ? 'critical' : 'medium'
          });
        }
        
        response.data.detailedControls[fw] = controls;
      });
    }

    return NextResponse.json(response);

  } catch (error) {
    console.error('Error fetching compliance status:', error);
    
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error',
        message: 'Failed to fetch compliance status',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, framework, controlId } = body;

    // Handle different compliance actions
    switch (action) {
      case 'trigger_assessment':
        return NextResponse.json({
          success: true,
          message: `Assessment triggered for ${framework}`,
          assessmentId: `ASSESS_${Date.now()}`,
          estimatedCompletion: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });

      case 'update_control':
        return NextResponse.json({
          success: true,
          message: `Control ${controlId} updated`,
          updatedAt: new Date().toISOString()
        });

      case 'generate_report':
        return NextResponse.json({
          success: true,
          message: 'Compliance report generation started',
          reportId: `REPORT_${Date.now()}`,
          estimatedCompletion: new Date(Date.now() + 30 * 60 * 1000).toISOString()
        });

      default:
        return NextResponse.json(
          { 
            success: false, 
            error: 'Invalid action',
            validActions: ['trigger_assessment', 'update_control', 'generate_report']
          },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('Error processing compliance action:', error);
    
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error',
        message: 'Failed to process compliance action',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}