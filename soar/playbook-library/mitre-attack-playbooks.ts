/**
 * Production-grade MITRE ATT&CK Mapped Playbook Library for SOAR
 * 
 * Comprehensive playbook library with MITRE ATT&CK framework mapping,
 * response playbooks for all major attack techniques, and automated
 * threat response orchestration for iSECTECH's cybersecurity platform.
 * 
 * Custom implementation with enterprise-grade security response automation.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// MITRE ATT&CK Mapping Schemas
export const MITREAttackTechniqueSchema = z.object({
  techniqueId: z.string(), // e.g., "T1566.001"
  techniqueName: z.string(),
  description: z.string(),
  
  // MITRE taxonomy
  tactic: z.string(), // e.g., "Initial Access"
  subTechnique: z.string().optional(),
  platforms: z.array(z.string()),
  dataSource: z.array(z.string()),
  
  // Detection capabilities
  detection: z.object({
    dataSourcesRequired: z.array(z.string()),
    detectionQueries: z.array(z.object({
      platform: z.string(),
      query: z.string(),
      description: z.string()
    })),
    indicators: z.array(z.string()),
    behavioralSignatures: z.array(z.string())
  }),
  
  // Mitigation strategies
  mitigation: z.object({
    mitigationId: z.string().optional(),
    mitigationName: z.string().optional(),
    description: z.string(),
    implementation: z.array(z.string())
  }),
  
  // Threat intelligence
  threatIntel: z.object({
    groups: z.array(z.string()), // Associated threat groups
    software: z.array(z.string()), // Associated malware/tools
    campaigns: z.array(z.string()), // Known campaigns using this technique
    prevalence: z.enum(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW']),
    sophistication: z.enum(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW'])
  }),
  
  // Response mapping
  responsePlaybooks: z.array(z.string()), // Playbook IDs
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const SOARPlaybookSchema = z.object({
  playbookId: z.string(),
  name: z.string(),
  description: z.string(),
  version: z.string(),
  
  // Classification
  category: z.enum([
    'INITIAL_ACCESS',
    'EXECUTION', 
    'PERSISTENCE',
    'PRIVILEGE_ESCALATION',
    'DEFENSE_EVASION',
    'CREDENTIAL_ACCESS',
    'DISCOVERY',
    'LATERAL_MOVEMENT',
    'COLLECTION',
    'COMMAND_AND_CONTROL',
    'EXFILTRATION',
    'IMPACT',
    'GENERAL_RESPONSE'
  ]),
  
  severity: z.enum(['P1_CRITICAL', 'P2_HIGH', 'P3_MEDIUM', 'P4_LOW']),
  complexity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH']),
  
  // MITRE ATT&CK mapping
  mitreMapping: z.object({
    techniques: z.array(z.string()), // MITRE technique IDs
    tactics: z.array(z.string()), // MITRE tactic names
    subTechniques: z.array(z.string()).optional(),
    mitigations: z.array(z.string()).optional()
  }),
  
  // Playbook structure
  workflow: z.object({
    steps: z.array(z.object({
      stepId: z.string(),
      name: z.string(),
      description: z.string(),
      type: z.enum(['DETECTION', 'ANALYSIS', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'DOCUMENTATION']),
      automationLevel: z.enum(['FULLY_AUTOMATED', 'SEMI_AUTOMATED', 'MANUAL']),
      estimatedDuration: z.number(), // minutes
      prerequisites: z.array(z.string()),
      actions: z.array(z.object({
        actionType: z.enum(['API_CALL', 'SCRIPT_EXECUTION', 'HUMAN_TASK', 'INTEGRATION_CALL']),
        description: z.string(),
        parameters: z.record(z.any()),
        expectedOutcome: z.string()
      })),
      successCriteria: z.array(z.string()),
      errorHandling: z.object({
        onFailure: z.enum(['RETRY', 'ESCALATE', 'ABORT', 'CONTINUE']),
        retryCount: z.number().default(3),
        escalationProcedure: z.string().optional()
      })
    })),
    dependencies: z.array(z.object({
      stepId: z.string(),
      dependsOn: z.array(z.string())
    }))
  }),
  
  // Triggers and conditions
  triggers: z.array(z.object({
    triggerType: z.enum(['ALERT', 'IOC_MATCH', 'BEHAVIORAL_DETECTION', 'MANUAL']),
    source: z.string(),
    conditions: z.record(z.any()),
    priority: z.number()
  })),
  
  // Required integrations
  integrations: z.array(z.object({
    system: z.string(),
    purpose: z.string(),
    required: z.boolean(),
    alternativeOptions: z.array(z.string())
  })),
  
  // Input/Output parameters
  inputs: z.array(z.object({
    name: z.string(),
    type: z.string(),
    required: z.boolean(),
    description: z.string(),
    defaultValue: z.any().optional()
  })),
  
  outputs: z.array(z.object({
    name: z.string(),
    type: z.string(),
    description: z.string()
  })),
  
  // Performance metrics
  sla: z.object({
    maxResponseTime: z.number(), // minutes
    maxContainmentTime: z.number(),
    maxResolutionTime: z.number(),
    targetSuccessRate: z.number() // percentage
  }),
  
  // Testing and validation
  testing: z.object({
    testCases: z.array(z.object({
      testId: z.string(),
      scenario: z.string(),
      expectedResult: z.string(),
      lastTested: z.date().optional(),
      passed: z.boolean().optional()
    })),
    validationChecklist: z.array(z.string())
  }),
  
  // Documentation
  documentation: z.object({
    overview: z.string(),
    prerequisites: z.string(),
    stepByStepGuide: z.string(),
    troubleshooting: z.string(),
    references: z.array(z.string())
  }),
  
  // Usage statistics
  statistics: z.object({
    totalExecutions: z.number().default(0),
    successfulExecutions: z.number().default(0),
    averageExecutionTime: z.number().default(0),
    lastExecuted: z.date().optional(),
    effectiveness: z.number().optional() // percentage
  }),
  
  // Lifecycle management
  status: z.enum(['DRAFT', 'TESTING', 'APPROVED', 'ACTIVE', 'DEPRECATED']),
  approvedBy: z.string().optional(),
  approvedAt: z.date().optional(),
  
  // Access control
  permissions: z.object({
    canExecute: z.array(z.string()),
    canModify: z.array(z.string()),
    canView: z.array(z.string())
  }),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const ThreatScenarioSchema = z.object({
  scenarioId: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Threat classification
  threatType: z.enum([
    'APT_CAMPAIGN',
    'RANSOMWARE_ATTACK',
    'PHISHING_CAMPAIGN',
    'MALWARE_INFECTION',
    'INSIDER_THREAT',
    'SUPPLY_CHAIN_ATTACK',
    'ZERO_DAY_EXPLOIT',
    'SOCIAL_ENGINEERING',
    'DATA_BREACH',
    'DDOS_ATTACK'
  ]),
  
  // Attack chain
  killChain: z.array(z.object({
    phase: z.string(),
    techniques: z.array(z.string()), // MITRE technique IDs
    description: z.string(),
    indicators: z.array(z.string()),
    detectionMethods: z.array(z.string())
  })),
  
  // Threat actor profile
  threatActor: z.object({
    group: z.string().optional(),
    motivation: z.array(z.string()),
    sophistication: z.enum(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW']),
    resources: z.enum(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW']),
    geography: z.array(z.string()),
    targets: z.array(z.string())
  }),
  
  // Response playbooks
  responsePlaybooks: z.array(z.object({
    playbookId: z.string(),
    phase: z.string(),
    priority: z.number(),
    mandatory: z.boolean()
  })),
  
  // Business impact
  impact: z.object({
    confidentiality: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    integrity: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    availability: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    businessImpact: z.string(),
    affectedAssets: z.array(z.string()),
    estimatedCost: z.number().optional()
  }),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export type MITREAttackTechnique = z.infer<typeof MITREAttackTechniqueSchema>;
export type SOARPlaybook = z.infer<typeof SOARPlaybookSchema>;
export type ThreatScenario = z.infer<typeof ThreatScenarioSchema>;

/**
 * MITRE ATT&CK Mapped Playbook Library Manager
 */
export class ISECTECHMITREPlaybookLibrary {
  private techniques: Map<string, MITREAttackTechnique> = new Map();
  private playbooks: Map<string, SOARPlaybook> = new Map();
  private threatScenarios: Map<string, ThreatScenario> = new Map();
  private techniqueToPlaybookMapping: Map<string, string[]> = new Map();

  constructor() {
    this.initializeLibrary();
  }

  /**
   * Initialize the MITRE ATT&CK mapped playbook library
   */
  private initializeLibrary(): void {
    console.log('Initializing iSECTECH MITRE ATT&CK Playbook Library...');
    
    // Initialize MITRE ATT&CK techniques
    this.initializeMITRETechniques();
    
    // Initialize response playbooks
    this.initializeResponsePlaybooks();
    
    // Initialize threat scenarios
    this.initializeThreatScenarios();
    
    // Create mappings
    this.createTechniquePlaybookMappings();
    
    console.log(`Library initialized with ${this.techniques.size} techniques, ${this.playbooks.size} playbooks, and ${this.threatScenarios.size} scenarios`);
  }

  /**
   * Initialize key MITRE ATT&CK techniques
   */
  private initializeMITRETechniques(): void {
    const techniques: Partial<MITREAttackTechnique>[] = [
      // Initial Access Techniques
      {
        techniqueId: 'T1566.001',
        techniqueName: 'Spearphishing Attachment',
        description: 'Adversaries may send spearphishing emails with a malicious attachment',
        tactic: 'Initial Access',
        platforms: ['Windows', 'macOS', 'Linux'],
        dataSource: ['Email Gateway', 'File Monitoring', 'Network Traffic'],
        detection: {
          dataSourcesRequired: ['Email Security Gateway', 'Email Logs', 'File Analysis'],
          detectionQueries: [
            {
              platform: 'Splunk',
              query: 'index=email sourcetype=email_gateway | search attachment_count>0 AND (file_type="exe" OR file_type="zip" OR file_type="doc")',
              description: 'Detect emails with suspicious attachments'
            },
            {
              platform: 'Elastic',
              query: 'event.module:email AND email.attachments.file.extension:(exe OR zip OR doc OR pdf)',
              description: 'Detect emails with potentially malicious file types'
            }
          ],
          indicators: ['Suspicious file attachments', 'Sender reputation', 'Email headers'],
          behavioralSignatures: ['Executable in zip archive', 'Macro-enabled documents', 'Double file extensions']
        },
        mitigation: {
          mitigationId: 'M1049',
          mitigationName: 'Antivirus/Antimalware',
          description: 'Use antivirus/antimalware software to scan email attachments',
          implementation: [
            'Deploy email security gateway with attachment scanning',
            'Enable real-time file scanning on endpoints',
            'Implement attachment sandboxing',
            'Configure email filtering rules'
          ]
        },
        threatIntel: {
          groups: ['APT1', 'APT28', 'APT29', 'Lazarus Group'],
          software: ['Emotet', 'TrickBot', 'Dridex'],
          campaigns: ['APT1 Comment Crew', 'Russian Election Interference'],
          prevalence: 'VERY_HIGH',
          sophistication: 'MEDIUM'
        },
        responsePlaybooks: ['pb-phishing-response', 'pb-malware-containment']
      },
      
      {
        techniqueId: 'T1078.004',
        techniqueName: 'Cloud Accounts',
        description: 'Adversaries may obtain and abuse credentials of existing cloud accounts',
        tactic: 'Defense Evasion',
        platforms: ['Azure AD', 'AWS', 'GCP', 'Office 365'],
        dataSource: ['Authentication Logs', 'Cloud Service Logs'],
        detection: {
          dataSourcesRequired: ['Azure AD Logs', 'AWS CloudTrail', 'GCP Audit Logs'],
          detectionQueries: [
            {
              platform: 'Azure Sentinel',
              query: 'SigninLogs | where ResultType != 0 or LocationDetails.city != "Normal_Location"',
              description: 'Detect anomalous cloud account sign-ins'
            },
            {
              platform: 'AWS CloudWatch',
              query: 'eventSource: signin.amazonaws.com AND errorCode: exists',
              description: 'Detect failed AWS console sign-ins'
            }
          ],
          indicators: ['Unusual login locations', 'Failed authentication attempts', 'Privilege escalation'],
          behavioralSignatures: ['Login from new device', 'Multiple failed attempts', 'Unusual access patterns']
        },
        mitigation: {
          mitigationId: 'M1032',
          mitigationName: 'Multi-factor Authentication',
          description: 'Use multi-factor authentication for cloud accounts',
          implementation: [
            'Enable MFA for all cloud accounts',
            'Implement conditional access policies',
            'Configure privileged access management',
            'Deploy identity governance solutions'
          ]
        },
        threatIntel: {
          groups: ['APT29', 'APT40', 'Lazarus Group'],
          software: ['Azure AD PowerShell', 'AWS CLI'],
          campaigns: ['SolarWinds Supply Chain', 'Cloud Hopper'],
          prevalence: 'HIGH',
          sophistication: 'HIGH'
        },
        responsePlaybooks: ['pb-account-compromise', 'pb-cloud-investigation']
      },
      
      {
        techniqueId: 'T1055',
        techniqueName: 'Process Injection',
        description: 'Adversaries may inject code into processes to evade defenses',
        tactic: 'Defense Evasion',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: ['Process Monitoring', 'API Monitoring'],
        detection: {
          dataSourcesRequired: ['EDR Logs', 'Process Creation Events', 'API Call Monitoring'],
          detectionQueries: [
            {
              platform: 'Windows Event Log',
              query: 'EventID:4688 AND Process_Command_Line:*CreateRemoteThread* OR *VirtualAllocEx*',
              description: 'Detect process injection APIs'
            },
            {
              platform: 'Sysmon',
              query: 'EventID:8 AND TargetImage:*svchost.exe AND NOT SourceImage:*system*',
              description: 'Detect unusual cross-process access'
            }
          ],
          indicators: ['Unusual process relationships', 'Suspicious API calls', 'Memory modifications'],
          behavioralSignatures: ['CreateRemoteThread API', 'VirtualAllocEx calls', 'Hollow process creation']
        },
        mitigation: {
          mitigationId: 'M1040',
          mitigationName: 'Behavior Prevention on Endpoint',
          description: 'Use endpoint behavioral analysis to detect process injection',
          implementation: [
            'Deploy EDR solutions with behavioral monitoring',
            'Enable process hollowing detection',
            'Configure API monitoring rules',
            'Implement memory protection mechanisms'
          ]
        },
        threatIntel: {
          groups: ['APT1', 'APT3', 'Carbanak', 'FIN7'],
          software: ['Cobalt Strike', 'Metasploit', 'PowerSploit'],
          campaigns: ['Carbanak Banking Heist', 'FIN7 Restaurant Chain Attacks'],
          prevalence: 'HIGH',
          sophistication: 'HIGH'
        },
        responsePlaybooks: ['pb-process-analysis', 'pb-memory-forensics']
      },
      
      {
        techniqueId: 'T1486',
        techniqueName: 'Data Encrypted for Impact',
        description: 'Adversaries may encrypt data on target systems to interrupt business operations',
        tactic: 'Impact',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: ['File Monitoring', 'Process Monitoring'],
        detection: {
          dataSourcesRequired: ['File System Monitoring', 'Process Monitoring', 'Network Traffic'],
          detectionQueries: [
            {
              platform: 'Sysmon',
              query: 'EventID:11 AND TargetFilename:*.encrypted OR *.locked OR *.crypt',
              description: 'Detect mass file encryption events'
            },
            {
              platform: 'Elastic',
              query: 'file.extension:(encrypted OR locked OR crypt) AND event.action:creation',
              description: 'Detect creation of encrypted files'
            }
          ],
          indicators: ['Rapid file modifications', 'Ransom notes', 'Encrypted file extensions'],
          behavioralSignatures: ['Mass file encryption', 'Ransom note creation', 'Shadow copy deletion']
        },
        mitigation: {
          mitigationId: 'M1053',
          mitigationName: 'Data Backup',
          description: 'Maintain secure backups to recover from ransomware',
          implementation: [
            'Implement automated backup solutions',
            'Store backups offline or immutable',
            'Test backup restoration procedures',
            'Deploy endpoint protection with ransomware detection'
          ]
        },
        threatIntel: {
          groups: ['Conti', 'REvil', 'Ryuk', 'Maze'],
          software: ['WannaCry', 'NotPetya', 'BadRabbit'],
          campaigns: ['WannaCry Global Attack', 'NotPetya Ukraine Attack'],
          prevalence: 'HIGH',
          sophistication: 'MEDIUM'
        },
        responsePlaybooks: ['pb-ransomware-response', 'pb-data-recovery']
      },
      
      {
        techniqueId: 'T1071.001',
        techniqueName: 'Web Protocols',
        description: 'Adversaries may communicate using application layer protocols to blend in with traffic',
        tactic: 'Command and Control',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: ['Network Traffic', 'Proxy Logs'],
        detection: {
          dataSourcesRequired: ['Network Monitoring', 'Web Proxy Logs', 'DNS Logs'],
          detectionQueries: [
            {
              platform: 'Splunk',
              query: 'sourcetype=proxy | stats count by dest_ip, url | where count > 100',
              description: 'Detect high-frequency web requests to suspicious domains'
            },
            {
              platform: 'Elastic',
              query: 'network.protocol:http AND url.domain:(NOT in whitelist) AND event.outcome:success',
              description: 'Detect web traffic to non-whitelisted domains'
            }
          ],
          indicators: ['Unusual HTTP patterns', 'Suspicious user agents', 'Encrypted payloads'],
          behavioralSignatures: ['Beaconing behavior', 'Base64 encoded data', 'Steganography']
        },
        mitigation: {
          mitigationId: 'M1031',
          mitigationName: 'Network Intrusion Prevention',
          description: 'Use network intrusion prevention to detect and block C2 traffic',
          implementation: [
            'Deploy web application firewalls',
            'Implement DNS filtering',
            'Configure proxy inspection',
            'Monitor network traffic for anomalies'
          ]
        },
        threatIntel: {
          groups: ['APT28', 'APT29', 'Lazarus Group'],
          software: ['HTTPS Backdoors', 'DNS Tunneling Tools'],
          campaigns: ['SolarWinds Attack', 'HAFNIUM Exchange Attacks'],
          prevalence: 'VERY_HIGH',
          sophistication: 'MEDIUM'
        },
        responsePlaybooks: ['pb-c2-investigation', 'pb-network-isolation']
      }
    ];

    techniques.forEach(technique => {
      this.addTechnique(technique);
    });

    console.log(`Initialized ${techniques.length} MITRE ATT&CK techniques`);
  }

  /**
   * Initialize response playbooks
   */
  private initializeResponsePlaybooks(): void {
    const playbooks: Partial<SOARPlaybook>[] = [
      // Phishing Response Playbook
      {
        playbookId: 'pb-phishing-response',
        name: 'Phishing Email Response',
        description: 'Comprehensive response to phishing email incidents',
        version: '2.1.0',
        category: 'INITIAL_ACCESS',
        severity: 'P2_HIGH',
        complexity: 'MEDIUM',
        
        mitreMapping: {
          techniques: ['T1566.001', 'T1566.002'],
          tactics: ['Initial Access'],
          subTechniques: ['Spearphishing Attachment', 'Spearphishing Link']
        },
        
        workflow: {
          steps: [
            {
              stepId: 'step-1',
              name: 'Alert Triage',
              description: 'Initial triage of phishing alert',
              type: 'ANALYSIS',
              automationLevel: 'SEMI_AUTOMATED',
              estimatedDuration: 5,
              prerequisites: ['Email security gateway configured', 'SIEM integration active'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Extract email metadata and headers',
                  parameters: { endpoint: '/api/email/extract', method: 'POST' },
                  expectedOutcome: 'Email headers and metadata extracted'
                },
                {
                  actionType: 'INTEGRATION_CALL',
                  description: 'Check sender reputation in threat intel',
                  parameters: { system: 'threat_intelligence', action: 'check_reputation' },
                  expectedOutcome: 'Sender reputation score obtained'
                }
              ],
              successCriteria: ['Email analyzed', 'Threat level assessed'],
              errorHandling: { onFailure: 'ESCALATE', retryCount: 3 }
            },
            
            {
              stepId: 'step-2',
              name: 'URL and Attachment Analysis',
              description: 'Deep analysis of email contents',
              type: 'ANALYSIS',
              automationLevel: 'FULLY_AUTOMATED',
              estimatedDuration: 10,
              prerequisites: ['Sandbox environment available'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Submit attachments to sandbox',
                  parameters: { endpoint: '/api/sandbox/analyze', timeout: 300 },
                  expectedOutcome: 'Malware analysis results'
                },
                {
                  actionType: 'API_CALL',
                  description: 'Check URLs against reputation services',
                  parameters: { endpoint: '/api/url/reputation' },
                  expectedOutcome: 'URL reputation scores'
                }
              ],
              successCriteria: ['All attachments analyzed', 'All URLs checked'],
              errorHandling: { onFailure: 'RETRY', retryCount: 2 }
            },
            
            {
              stepId: 'step-3',
              name: 'Impact Assessment',
              description: 'Assess potential impact and affected users',
              type: 'ANALYSIS',
              automationLevel: 'SEMI_AUTOMATED',
              estimatedDuration: 15,
              prerequisites: ['User directory access', 'Email logs access'],
              actions: [
                {
                  actionType: 'SCRIPT_EXECUTION',
                  description: 'Search for similar emails in environment',
                  parameters: { script: 'find_similar_emails.py', timeout: 600 },
                  expectedOutcome: 'List of similar emails and recipients'
                },
                {
                  actionType: 'API_CALL',
                  description: 'Check if users clicked links or opened attachments',
                  parameters: { endpoint: '/api/email/interaction' },
                  expectedOutcome: 'User interaction data'
                }
              ],
              successCriteria: ['Campaign scope identified', 'Affected users listed'],
              errorHandling: { onFailure: 'CONTINUE', retryCount: 1 }
            },
            
            {
              stepId: 'step-4',
              name: 'Email Quarantine',
              description: 'Quarantine malicious emails across environment',
              type: 'CONTAINMENT',
              automationLevel: 'FULLY_AUTOMATED',
              estimatedDuration: 5,
              prerequisites: ['Email admin privileges'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Quarantine emails in user mailboxes',
                  parameters: { endpoint: '/api/email/quarantine', method: 'POST' },
                  expectedOutcome: 'Emails quarantined successfully'
                },
                {
                  actionType: 'API_CALL',
                  description: 'Block sender at email gateway',
                  parameters: { endpoint: '/api/gateway/block_sender' },
                  expectedOutcome: 'Sender blocked at gateway'
                }
              ],
              successCriteria: ['All malicious emails quarantined', 'Sender blocked'],
              errorHandling: { onFailure: 'ESCALATE', retryCount: 2 }
            },
            
            {
              stepId: 'step-5',
              name: 'User Notification',
              description: 'Notify affected users and provide guidance',
              type: 'RECOVERY',
              automationLevel: 'SEMI_AUTOMATED',
              estimatedDuration: 10,
              prerequisites: ['Communication templates configured'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Send security alert to affected users',
                  parameters: { endpoint: '/api/notification/send', template: 'phishing_alert' },
                  expectedOutcome: 'Users notified of incident'
                },
                {
                  actionType: 'HUMAN_TASK',
                  description: 'Review notification content and approve',
                  parameters: { assignee: 'security_team', priority: 'high' },
                  expectedOutcome: 'Notification approved and sent'
                }
              ],
              successCriteria: ['All users notified', 'Security guidance provided'],
              errorHandling: { onFailure: 'CONTINUE', retryCount: 1 }
            },
            
            {
              stepId: 'step-6',
              name: 'Incident Documentation',
              description: 'Document incident details and response actions',
              type: 'DOCUMENTATION',
              automationLevel: 'SEMI_AUTOMATED',
              estimatedDuration: 20,
              prerequisites: ['Case management system configured'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Create incident record in case management',
                  parameters: { endpoint: '/api/cases/create', category: 'phishing' },
                  expectedOutcome: 'Incident case created'
                },
                {
                  actionType: 'SCRIPT_EXECUTION',
                  description: 'Generate incident report',
                  parameters: { script: 'generate_incident_report.py' },
                  expectedOutcome: 'Comprehensive incident report'
                }
              ],
              successCriteria: ['Incident documented', 'Report generated'],
              errorHandling: { onFailure: 'CONTINUE', retryCount: 1 }
            }
          ],
          dependencies: [
            { stepId: 'step-2', dependsOn: ['step-1'] },
            { stepId: 'step-3', dependsOn: ['step-1', 'step-2'] },
            { stepId: 'step-4', dependsOn: ['step-2'] },
            { stepId: 'step-5', dependsOn: ['step-3', 'step-4'] },
            { stepId: 'step-6', dependsOn: ['step-5'] }
          ]
        },
        
        triggers: [
          {
            triggerType: 'ALERT',
            source: 'email_security_gateway',
            conditions: { alert_type: 'phishing', confidence: { $gte: 0.7 } },
            priority: 1
          }
        ],
        
        integrations: [
          { system: 'Email Gateway', purpose: 'Email analysis and quarantine', required: true, alternativeOptions: [] },
          { system: 'Threat Intelligence', purpose: 'Reputation checking', required: true, alternativeOptions: ['VirusTotal', 'ThreatConnect'] },
          { system: 'Sandbox', purpose: 'Malware analysis', required: true, alternativeOptions: ['Cuckoo', 'Any.run'] }
        ],
        
        sla: {
          maxResponseTime: 15, // 15 minutes
          maxContainmentTime: 60, // 1 hour
          maxResolutionTime: 240, // 4 hours
          targetSuccessRate: 95
        },
        
        testing: {
          testCases: [
            {
              testId: 'test-phish-1',
              scenario: 'Malicious attachment detection',
              expectedResult: 'Email quarantined within 15 minutes',
              passed: true
            },
            {
              testId: 'test-phish-2',
              scenario: 'URL reputation checking',
              expectedResult: 'Malicious URLs identified and blocked',
              passed: true
            }
          ],
          validationChecklist: [
            'All email sources configured',
            'Sandbox integration tested',
            'Quarantine mechanism verified',
            'Notification templates validated'
          ]
        },
        
        documentation: {
          overview: 'This playbook handles phishing email incidents from detection through resolution',
          prerequisites: 'Email security gateway, threat intelligence feeds, sandbox environment',
          stepByStepGuide: 'Detailed execution guide available in playbook documentation',
          troubleshooting: 'Common issues and resolution steps documented',
          references: ['NIST IR Framework', 'MITRE ATT&CK', 'SANS Incident Response']
        },
        
        status: 'ACTIVE',
        permissions: {
          canExecute: ['soc_analyst', 'incident_responder'],
          canModify: ['security_engineer', 'playbook_admin'],
          canView: ['security_team']
        }
      },
      
      // Ransomware Response Playbook
      {
        playbookId: 'pb-ransomware-response',
        name: 'Ransomware Incident Response',
        description: 'Emergency response to ransomware infections',
        version: '1.5.0',
        category: 'IMPACT',
        severity: 'P1_CRITICAL',
        complexity: 'HIGH',
        
        mitreMapping: {
          techniques: ['T1486', 'T1490', 'T1083'],
          tactics: ['Impact', 'Discovery'],
          subTechniques: ['Data Encrypted for Impact', 'Inhibit System Recovery']
        },
        
        workflow: {
          steps: [
            {
              stepId: 'step-1',
              name: 'Immediate Isolation',
              description: 'Immediately isolate affected systems',
              type: 'CONTAINMENT',
              automationLevel: 'FULLY_AUTOMATED',
              estimatedDuration: 2,
              prerequisites: ['EDR deployment', 'Network segmentation'],
              actions: [
                {
                  actionType: 'API_CALL',
                  description: 'Isolate infected endpoints via EDR',
                  parameters: { endpoint: '/api/edr/isolate', urgency: 'critical' },
                  expectedOutcome: 'Endpoints isolated from network'
                },
                {
                  actionType: 'API_CALL',
                  description: 'Block affected user accounts',
                  parameters: { endpoint: '/api/identity/disable_accounts' },
                  expectedOutcome: 'User accounts disabled'
                }
              ],
              successCriteria: ['All affected systems isolated', 'Lateral movement prevented'],
              errorHandling: { onFailure: 'ESCALATE', retryCount: 1 }
            },
            
            {
              stepId: 'step-2',
              name: 'Scope Assessment',
              description: 'Determine full scope of ransomware infection',
              type: 'ANALYSIS',
              automationLevel: 'SEMI_AUTOMATED',
              estimatedDuration: 30,
              prerequisites: ['Network monitoring tools', 'Asset inventory'],
              actions: [
                {
                  actionType: 'SCRIPT_EXECUTION',
                  description: 'Scan network for ransomware indicators',
                  parameters: { script: 'ransomware_hunter.py', scope: 'enterprise' },
                  expectedOutcome: 'Complete infection scope identified'
                },
                {
                  actionType: 'API_CALL',
                  description: 'Check backup systems status',
                  parameters: { endpoint: '/api/backup/status' },
                  expectedOutcome: 'Backup integrity verified'
                }
              ],
              successCriteria: ['Infection scope mapped', 'Backup status confirmed'],
              errorHandling: { onFailure: 'CONTINUE', retryCount: 2 }
            }
          ],
          dependencies: [
            { stepId: 'step-2', dependsOn: ['step-1'] }
          ]
        },
        
        sla: {
          maxResponseTime: 5, // 5 minutes
          maxContainmentTime: 15, // 15 minutes
          maxResolutionTime: 1440, // 24 hours
          targetSuccessRate: 98
        }
      }
    ];

    playbooks.forEach(playbook => {
      this.addPlaybook(playbook);
    });

    console.log(`Initialized ${playbooks.length} response playbooks`);
  }

  /**
   * Initialize threat scenarios
   */
  private initializeThreatScenarios(): void {
    const scenarios: Partial<ThreatScenario>[] = [
      {
        name: 'APT Spearphishing Campaign',
        description: 'Advanced persistent threat using targeted spearphishing',
        threatType: 'APT_CAMPAIGN',
        
        killChain: [
          {
            phase: 'Initial Access',
            techniques: ['T1566.001'],
            description: 'Spearphishing with malicious attachments',
            indicators: ['Suspicious email attachments', 'Targeted recipients'],
            detectionMethods: ['Email gateway analysis', 'Sandbox detonation']
          },
          {
            phase: 'Execution',
            techniques: ['T1059.001'],
            description: 'PowerShell script execution',
            indicators: ['PowerShell execution', 'Encoded commands'],
            detectionMethods: ['PowerShell logging', 'Process monitoring']
          },
          {
            phase: 'Persistence',
            techniques: ['T1547.001'],
            description: 'Registry run keys modification',
            indicators: ['Registry modifications', 'Startup program changes'],
            detectionMethods: ['Registry monitoring', 'System integrity checks']
          }
        ],
        
        threatActor: {
          group: 'APT28',
          motivation: ['Espionage', 'Intelligence gathering'],
          sophistication: 'VERY_HIGH',
          resources: 'HIGH',
          geography: ['Russia', 'Eastern Europe'],
          targets: ['Government', 'Defense contractors', 'Think tanks']
        },
        
        responsePlaybooks: [
          { playbookId: 'pb-phishing-response', phase: 'Initial Access', priority: 1, mandatory: true },
          { playbookId: 'pb-malware-containment', phase: 'Execution', priority: 1, mandatory: true },
          { playbookId: 'pb-persistence-analysis', phase: 'Persistence', priority: 2, mandatory: false }
        ],
        
        impact: {
          confidentiality: 'HIGH',
          integrity: 'MEDIUM',
          availability: 'LOW',
          businessImpact: 'Potential intellectual property theft and espionage',
          affectedAssets: ['Email systems', 'Workstations', 'File servers'],
          estimatedCost: 500000
        }
      },
      
      {
        name: 'Ransomware Attack Chain',
        description: 'Multi-stage ransomware deployment and execution',
        threatType: 'RANSOMWARE_ATTACK',
        
        killChain: [
          {
            phase: 'Initial Access',
            techniques: ['T1566.001', 'T1190'],
            description: 'Entry via phishing or exploit',
            indicators: ['Suspicious emails', 'Exploit attempts'],
            detectionMethods: ['Email security', 'Vulnerability scanning']
          },
          {
            phase: 'Privilege Escalation',
            techniques: ['T1068'],
            description: 'Local privilege escalation',
            indicators: ['Privilege escalation attempts', 'System modifications'],
            detectionMethods: ['Endpoint monitoring', 'Privilege monitoring']
          },
          {
            phase: 'Impact',
            techniques: ['T1486', 'T1490'],
            description: 'File encryption and backup destruction',
            indicators: ['Mass file encryption', 'Backup deletion', 'Ransom notes'],
            detectionMethods: ['File monitoring', 'Backup monitoring']
          }
        ],
        
        threatActor: {
          group: 'Conti',
          motivation: ['Financial gain'],
          sophistication: 'HIGH',
          resources: 'HIGH',
          geography: ['Russia', 'Eastern Europe'],
          targets: ['Healthcare', 'Manufacturing', 'Government']
        },
        
        responsePlaybooks: [
          { playbookId: 'pb-ransomware-response', phase: 'Impact', priority: 1, mandatory: true },
          { playbookId: 'pb-data-recovery', phase: 'Recovery', priority: 1, mandatory: true }
        ],
        
        impact: {
          confidentiality: 'MEDIUM',
          integrity: 'HIGH',
          availability: 'HIGH',
          businessImpact: 'Business operations disruption and potential data loss',
          affectedAssets: ['File servers', 'Databases', 'Backup systems'],
          estimatedCost: 2000000
        }
      }
    ];

    scenarios.forEach(scenario => {
      this.addThreatScenario(scenario);
    });

    console.log(`Initialized ${scenarios.length} threat scenarios`);
  }

  /**
   * Create technique to playbook mappings
   */
  private createTechniquePlaybookMappings(): void {
    for (const technique of this.techniques.values()) {
      this.techniqueToPlaybookMapping.set(technique.techniqueId, technique.responsePlaybooks);
    }
    
    console.log('Created technique to playbook mappings');
  }

  /**
   * Add MITRE ATT&CK technique
   */
  public addTechnique(techniqueData: Partial<MITREAttackTechnique>): MITREAttackTechnique {
    const technique: MITREAttackTechnique = {
      techniqueId: techniqueData.techniqueId || 'T0000',
      techniqueName: techniqueData.techniqueName || 'Unknown Technique',
      description: techniqueData.description || '',
      tactic: techniqueData.tactic || 'Unknown',
      subTechnique: techniqueData.subTechnique,
      platforms: techniqueData.platforms || [],
      dataSource: techniqueData.dataSource || [],
      detection: {
        dataSourcesRequired: [],
        detectionQueries: [],
        indicators: [],
        behavioralSignatures: [],
        ...techniqueData.detection
      },
      mitigation: {
        description: '',
        implementation: [],
        ...techniqueData.mitigation
      },
      threatIntel: {
        groups: [],
        software: [],
        campaigns: [],
        prevalence: 'MEDIUM',
        sophistication: 'MEDIUM',
        ...techniqueData.threatIntel
      },
      responsePlaybooks: techniqueData.responsePlaybooks || [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedTechnique = MITREAttackTechniqueSchema.parse(technique);
    this.techniques.set(validatedTechnique.techniqueId, validatedTechnique);
    
    return validatedTechnique;
  }

  /**
   * Add response playbook
   */
  public addPlaybook(playbookData: Partial<SOARPlaybook>): SOARPlaybook {
    const playbook: SOARPlaybook = {
      playbookId: playbookData.playbookId || crypto.randomUUID(),
      name: playbookData.name || 'New Playbook',
      description: playbookData.description || '',
      version: playbookData.version || '1.0.0',
      category: playbookData.category || 'GENERAL_RESPONSE',
      severity: playbookData.severity || 'P3_MEDIUM',
      complexity: playbookData.complexity || 'MEDIUM',
      mitreMapping: {
        techniques: [],
        tactics: [],
        ...playbookData.mitreMapping
      },
      workflow: {
        steps: [],
        dependencies: [],
        ...playbookData.workflow
      },
      triggers: playbookData.triggers || [],
      integrations: playbookData.integrations || [],
      inputs: playbookData.inputs || [],
      outputs: playbookData.outputs || [],
      sla: {
        maxResponseTime: 30,
        maxContainmentTime: 120,
        maxResolutionTime: 480,
        targetSuccessRate: 90,
        ...playbookData.sla
      },
      testing: {
        testCases: [],
        validationChecklist: [],
        ...playbookData.testing
      },
      documentation: {
        overview: '',
        prerequisites: '',
        stepByStepGuide: '',
        troubleshooting: '',
        references: [],
        ...playbookData.documentation
      },
      statistics: {
        totalExecutions: 0,
        successfulExecutions: 0,
        averageExecutionTime: 0,
        ...playbookData.statistics
      },
      status: playbookData.status || 'DRAFT',
      permissions: {
        canExecute: [],
        canModify: [],
        canView: [],
        ...playbookData.permissions
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedPlaybook = SOARPlaybookSchema.parse(playbook);
    this.playbooks.set(validatedPlaybook.playbookId, validatedPlaybook);
    
    return validatedPlaybook;
  }

  /**
   * Add threat scenario
   */
  public addThreatScenario(scenarioData: Partial<ThreatScenario>): ThreatScenario {
    const scenario: ThreatScenario = {
      scenarioId: scenarioData.scenarioId || crypto.randomUUID(),
      name: scenarioData.name || 'New Threat Scenario',
      description: scenarioData.description || '',
      threatType: scenarioData.threatType || 'APT_CAMPAIGN',
      killChain: scenarioData.killChain || [],
      threatActor: {
        motivation: [],
        sophistication: 'MEDIUM',
        resources: 'MEDIUM',
        geography: [],
        targets: [],
        ...scenarioData.threatActor
      },
      responsePlaybooks: scenarioData.responsePlaybooks || [],
      impact: {
        confidentiality: 'MEDIUM',
        integrity: 'MEDIUM',
        availability: 'MEDIUM',
        businessImpact: '',
        affectedAssets: [],
        ...scenarioData.impact
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedScenario = ThreatScenarioSchema.parse(scenario);
    this.threatScenarios.set(validatedScenario.scenarioId, validatedScenario);
    
    return validatedScenario;
  }

  /**
   * Get playbooks for MITRE technique
   */
  public getPlaybooksForTechnique(techniqueId: string): SOARPlaybook[] {
    const playbookIds = this.techniqueToPlaybookMapping.get(techniqueId) || [];
    return playbookIds.map(id => this.playbooks.get(id)).filter(Boolean) as SOARPlaybook[];
  }

  /**
   * Generate attack-to-response mapping report
   */
  public generateAttackResponseMapping(): any {
    const mappings = new Map<string, any>();
    
    for (const [techniqueId, technique] of this.techniques.entries()) {
      const responsePlaybooks = this.getPlaybooksForTechnique(techniqueId);
      
      mappings.set(techniqueId, {
        technique: {
          id: technique.techniqueId,
          name: technique.techniqueName,
          tactic: technique.tactic,
          prevalence: technique.threatIntel.prevalence,
          sophistication: technique.threatIntel.sophistication
        },
        responsePlaybooks: responsePlaybooks.map(pb => ({
          id: pb.playbookId,
          name: pb.name,
          category: pb.category,
          severity: pb.severity,
          complexity: pb.complexity,
          sla: pb.sla
        })),
        coverage: responsePlaybooks.length > 0 ? 'COVERED' : 'NOT_COVERED',
        gapAnalysis: responsePlaybooks.length === 0 ? 'Missing response playbook' : null
      });
    }
    
    return {
      totalTechniques: this.techniques.size,
      coveredTechniques: Array.from(mappings.values()).filter(m => m.coverage === 'COVERED').length,
      coveragePercentage: (Array.from(mappings.values()).filter(m => m.coverage === 'COVERED').length / this.techniques.size) * 100,
      mappings: Array.from(mappings.values()),
      gapAnalysis: Array.from(mappings.values()).filter(m => m.coverage === 'NOT_COVERED')
    };
  }

  /**
   * Generate comprehensive library report
   */
  public generateLibraryReport(): any {
    const attackResponseMapping = this.generateAttackResponseMapping();
    
    return {
      summary: {
        totalTechniques: this.techniques.size,
        totalPlaybooks: this.playbooks.size,
        totalScenarios: this.threatScenarios.size,
        coveragePercentage: attackResponseMapping.coveragePercentage
      },
      
      techniqueAnalysis: {
        byTactic: this.groupBy(Array.from(this.techniques.values()), 'tactic'),
        byPrevalence: this.groupBy(Array.from(this.techniques.values()), t => t.threatIntel.prevalence),
        bySophistication: this.groupBy(Array.from(this.techniques.values()), t => t.threatIntel.sophistication)
      },
      
      playbookAnalysis: {
        byCategory: this.groupBy(Array.from(this.playbooks.values()), 'category'),
        bySeverity: this.groupBy(Array.from(this.playbooks.values()), 'severity'),
        byComplexity: this.groupBy(Array.from(this.playbooks.values()), 'complexity'),
        byStatus: this.groupBy(Array.from(this.playbooks.values()), 'status')
      },
      
      attackResponseMapping,
      
      threatScenarioAnalysis: {
        byThreatType: this.groupBy(Array.from(this.threatScenarios.values()), 'threatType'),
        byImpactLevel: this.analyzeImpactLevels(),
        bySophistication: this.groupBy(Array.from(this.threatScenarios.values()), s => s.threatActor.sophistication)
      },
      
      recommendations: this.generateLibraryRecommendations()
    };
  }

  // Private helper methods
  private groupBy<T>(array: T[], keyOrFunc: keyof T | ((item: T) => any)): Record<string, number> {
    return array.reduce((acc, item) => {
      const key = typeof keyOrFunc === 'function' ? keyOrFunc(item) : item[keyOrFunc];
      const keyStr = String(key);
      acc[keyStr] = (acc[keyStr] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private analyzeImpactLevels(): any {
    const scenarios = Array.from(this.threatScenarios.values());
    return {
      highConfidentialityImpact: scenarios.filter(s => s.impact.confidentiality === 'HIGH').length,
      highIntegrityImpact: scenarios.filter(s => s.impact.integrity === 'HIGH').length,
      highAvailabilityImpact: scenarios.filter(s => s.impact.availability === 'HIGH').length
    };
  }

  private generateLibraryRecommendations(): string[] {
    const recommendations = [];
    const attackResponseMapping = this.generateAttackResponseMapping();
    
    if (attackResponseMapping.coveragePercentage < 80) {
      recommendations.push('Increase playbook coverage for MITRE ATT&CK techniques');
    }
    
    const highPrevalenceTechniques = Array.from(this.techniques.values())
      .filter(t => t.threatIntel.prevalence === 'VERY_HIGH' || t.threatIntel.prevalence === 'HIGH');
    
    const uncoveredHighPrevalence = highPrevalenceTechniques.filter(t => 
      !this.techniqueToPlaybookMapping.has(t.techniqueId) || 
      this.techniqueToPlaybookMapping.get(t.techniqueId)!.length === 0
    );
    
    if (uncoveredHighPrevalence.length > 0) {
      recommendations.push('Prioritize playbooks for high-prevalence attack techniques');
    }
    
    const draftPlaybooks = Array.from(this.playbooks.values()).filter(p => p.status === 'DRAFT');
    if (draftPlaybooks.length > 0) {
      recommendations.push('Complete testing and approval for draft playbooks');
    }
    
    return recommendations;
  }

  /**
   * Public getters for testing and external access
   */
  public getTechnique(techniqueId: string): MITREAttackTechnique | null {
    return this.techniques.get(techniqueId) || null;
  }

  public getAllTechniques(): MITREAttackTechnique[] {
    return Array.from(this.techniques.values());
  }

  public getPlaybook(playbookId: string): SOARPlaybook | null {
    return this.playbooks.get(playbookId) || null;
  }

  public getAllPlaybooks(): SOARPlaybook[] {
    return Array.from(this.playbooks.values());
  }

  public getThreatScenario(scenarioId: string): ThreatScenario | null {
    return this.threatScenarios.get(scenarioId) || null;
  }

  public getAllThreatScenarios(): ThreatScenario[] {
    return Array.from(this.threatScenarios.values());
  }

  public getTechniqueToPlaybookMapping(): Map<string, string[]> {
    return this.techniqueToPlaybookMapping;
  }
}

// Export production-ready MITRE ATT&CK playbook library
export const isectechMITREPlaybookLibrary = new ISECTECHMITREPlaybookLibrary();