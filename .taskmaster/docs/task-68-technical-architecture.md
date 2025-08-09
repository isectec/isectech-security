# Customer Onboarding Automation - Technical Architecture
## Task 68: Detailed Technical Specifications

### SYSTEM ARCHITECTURE OVERVIEW

#### **High-Level Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Customer UI   │    │  Onboarding     │    │  Integration    │
│   (Next.js)     │◄──►│  Workflow       │◄──►│  Layer          │
│                 │    │  Engine         │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Multi-Tenant   │    │  Workflow       │    │  External APIs  │
│  Database       │    │  State Store    │    │  CRM/Support    │
│  (PostgreSQL)   │    │  (Redis)        │    │  Email/Analytics│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### **Component Architecture**
```typescript
// Core system components
interface OnboardingSystem {
  workflowEngine: WorkflowEngine;
  tenantManager: TenantManager;
  formBuilder: DynamicFormBuilder;
  communicationEngine: CommunicationEngine;
  integrationHub: IntegrationHub;
  analyticsCollector: AnalyticsCollector;
  complianceValidator: ComplianceValidator;
  auditLogger: AuditLogger;
}
```

### WORKFLOW ENGINE SPECIFICATION

#### **Workflow State Machine**
```typescript
interface OnboardingWorkflow {
  id: string;
  tenantId: string;
  customerId: string;
  templateId: string;
  currentStep: string;
  status: 'pending' | 'in-progress' | 'completed' | 'failed' | 'cancelled';
  context: WorkflowContext;
  steps: WorkflowStep[];
  metadata: WorkflowMetadata;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
}

interface WorkflowStep {
  id: string;
  name: string;
  type: 'form' | 'automation' | 'review' | 'integration' | 'notification';
  config: StepConfiguration;
  prerequisites: string[];
  status: 'pending' | 'in-progress' | 'completed' | 'failed' | 'skipped';
  data: any;
  error?: string;
  startedAt?: Date;
  completedAt?: Date;
}

interface WorkflowContext {
  customer: CustomerProfile;
  subscription: SubscriptionDetails;
  selectedServices: string[];
  complianceRequirements: string[];
  customizations: any;
  progress: ProgressMetrics;
}
```

#### **Workflow Engine Implementation**
```typescript
class WorkflowEngine {
  private workflows: Map<string, OnboardingWorkflow> = new Map();
  private stepExecutors: Map<string, StepExecutor> = new Map();

  async startWorkflow(
    tenantId: string,
    customerId: string,
    templateId: string,
    initialData: any
  ): Promise<OnboardingWorkflow> {
    // Load template and create workflow instance
    const template = await this.loadWorkflowTemplate(templateId);
    const workflow = this.createWorkflowInstance(
      tenantId, 
      customerId, 
      template, 
      initialData
    );
    
    // Initialize workflow context
    workflow.context = await this.buildWorkflowContext(
      tenantId, 
      customerId, 
      initialData
    );
    
    // Start first step
    await this.executeNextStep(workflow);
    
    return workflow;
  }

  async executeStep(workflowId: string, stepId: string): Promise<void> {
    const workflow = this.workflows.get(workflowId);
    const step = workflow.steps.find(s => s.id === stepId);
    const executor = this.stepExecutors.get(step.type);
    
    try {
      step.status = 'in-progress';
      step.startedAt = new Date();
      
      const result = await executor.execute(step, workflow.context);
      
      step.status = 'completed';
      step.data = result;
      step.completedAt = new Date();
      
      // Update workflow progress
      await this.updateWorkflowProgress(workflow);
      
      // Execute next step if prerequisites met
      await this.executeNextStep(workflow);
      
    } catch (error) {
      step.status = 'failed';
      step.error = error.message;
      
      // Handle error recovery
      await this.handleStepError(workflow, step, error);
    }
  }
}
```

### DATABASE SCHEMA SPECIFICATION

#### **Core Tables**
```sql
-- Onboarding workflows
CREATE TABLE onboarding_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    customer_id UUID NOT NULL,
    template_id UUID NOT NULL REFERENCES workflow_templates(id),
    current_step_id UUID,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    context JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    
    CONSTRAINT valid_status CHECK (status IN (
        'pending', 'in-progress', 'completed', 'failed', 'cancelled'
    ))
);

-- Workflow steps
CREATE TABLE workflow_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES onboarding_workflows(id) ON DELETE CASCADE,
    step_name VARCHAR(100) NOT NULL,
    step_type VARCHAR(50) NOT NULL,
    step_order INTEGER NOT NULL,
    configuration JSONB NOT NULL DEFAULT '{}',
    prerequisites TEXT[] DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    step_data JSONB DEFAULT '{}',
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_step_status CHECK (status IN (
        'pending', 'in-progress', 'completed', 'failed', 'skipped'
    ))
);

-- Workflow templates
CREATE TABLE workflow_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    version VARCHAR(20) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    target_audience JSONB DEFAULT '{}',
    steps_configuration JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(name, version)
);

-- Customer profiles for onboarding
CREATE TABLE customer_onboarding_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    customer_id UUID NOT NULL,
    industry VARCHAR(100),
    company_size VARCHAR(50),
    use_cases TEXT[],
    compliance_requirements TEXT[],
    technical_contact JSONB,
    business_contact JSONB,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, customer_id)
);

-- Dynamic form schemas
CREATE TABLE dynamic_forms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    form_name VARCHAR(100) NOT NULL,
    schema_version VARCHAR(20) NOT NULL,
    form_schema JSONB NOT NULL,
    validation_rules JSONB DEFAULT '{}',
    conditional_logic JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Form submissions
CREATE TABLE form_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_step_id UUID NOT NULL REFERENCES workflow_steps(id),
    form_id UUID NOT NULL REFERENCES dynamic_forms(id),
    submission_data JSONB NOT NULL,
    validation_results JSONB DEFAULT '{}',
    submitted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    submitted_by UUID NOT NULL
);

-- Communication templates
CREATE TABLE communication_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    template_name VARCHAR(100) NOT NULL,
    template_type VARCHAR(50) NOT NULL, -- email, sms, in-app
    subject_template TEXT,
    content_template TEXT NOT NULL,
    variables JSONB DEFAULT '{}',
    trigger_conditions JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Communication logs
CREATE TABLE communication_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES onboarding_workflows(id),
    template_id UUID NOT NULL REFERENCES communication_templates(id),
    recipient_id UUID NOT NULL,
    communication_type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    sent_at TIMESTAMP,
    delivered_at TIMESTAMP,
    opened_at TIMESTAMP,
    clicked_at TIMESTAMP,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Integration logs
CREATE TABLE integration_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    workflow_id UUID REFERENCES onboarding_workflows(id),
    integration_type VARCHAR(50) NOT NULL, -- crm, support, billing, etc.
    operation VARCHAR(50) NOT NULL, -- create, update, sync, etc.
    request_data JSONB,
    response_data JSONB,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Compliance checkpoints
CREATE TABLE compliance_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_step_id UUID NOT NULL REFERENCES workflow_steps(id),
    checkpoint_type VARCHAR(100) NOT NULL,
    requirements JSONB NOT NULL,
    validation_result JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    validated_at TIMESTAMP,
    validated_by UUID,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Audit logs for onboarding
CREATE TABLE onboarding_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    workflow_id UUID REFERENCES onboarding_workflows(id),
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Analytics events
CREATE TABLE onboarding_analytics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    workflow_id UUID REFERENCES onboarding_workflows(id),
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    event_properties JSONB DEFAULT '{}',
    user_properties JSONB DEFAULT '{}',
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    session_id UUID
);

-- Row Level Security
ALTER TABLE onboarding_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_onboarding_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_forms ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE communication_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE communication_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_analytics ENABLE ROW LEVEL SECURITY;

-- RLS Policies (example for onboarding_workflows)
CREATE POLICY tenant_isolation_onboarding_workflows 
ON onboarding_workflows 
FOR ALL 
USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

### API SPECIFICATION

#### **Core API Endpoints**
```typescript
// Workflow Management API
interface OnboardingAPI {
  // Start new onboarding workflow
  POST /api/v1/onboarding/workflows
  body: {
    customerId: string;
    templateId: string;
    initialData: any;
  }

  // Get workflow status
  GET /api/v1/onboarding/workflows/{workflowId}
  
  // Update workflow step
  POST /api/v1/onboarding/workflows/{workflowId}/steps/{stepId}/complete
  body: {
    stepData: any;
  }

  // Get next step
  GET /api/v1/onboarding/workflows/{workflowId}/next-step

  // Submit form data
  POST /api/v1/onboarding/forms/{formId}/submit
  body: {
    workflowStepId: string;
    formData: any;
  }

  // Get customer onboarding profile
  GET /api/v1/onboarding/customers/{customerId}/profile

  // Update customer profile
  PUT /api/v1/onboarding/customers/{customerId}/profile
  body: CustomerProfile;

  // Get onboarding templates
  GET /api/v1/onboarding/templates

  // Analytics endpoints
  GET /api/v1/onboarding/analytics/funnel
  GET /api/v1/onboarding/analytics/completion-rates
  GET /api/v1/onboarding/analytics/drop-offs
}
```

#### **API Implementation Example**
```typescript
// Workflow API Controller
@Controller('api/v1/onboarding/workflows')
@UseGuards(TenantAuthGuard)
export class OnboardingWorkflowController {
  constructor(
    private readonly workflowService: WorkflowService,
    private readonly analyticsService: AnalyticsService
  ) {}

  @Post()
  async startWorkflow(
    @TenantId() tenantId: string,
    @Body() createWorkflowDto: CreateWorkflowDto,
    @User() user: AuthenticatedUser
  ): Promise<OnboardingWorkflow> {
    // Validate customer exists and belongs to tenant
    await this.validateCustomer(tenantId, createWorkflowDto.customerId);
    
    // Start workflow
    const workflow = await this.workflowService.startWorkflow(
      tenantId,
      createWorkflowDto.customerId,
      createWorkflowDto.templateId,
      createWorkflowDto.initialData
    );
    
    // Track analytics event
    await this.analyticsService.trackEvent(tenantId, {
      event: 'onboarding_started',
      workflowId: workflow.id,
      customerId: createWorkflowDto.customerId,
      templateId: createWorkflowDto.templateId,
      userId: user.id
    });
    
    return workflow;
  }

  @Get(':workflowId')
  async getWorkflow(
    @TenantId() tenantId: string,
    @Param('workflowId') workflowId: string
  ): Promise<OnboardingWorkflow> {
    return await this.workflowService.getWorkflow(tenantId, workflowId);
  }

  @Post(':workflowId/steps/:stepId/complete')
  async completeStep(
    @TenantId() tenantId: string,
    @Param('workflowId') workflowId: string,
    @Param('stepId') stepId: string,
    @Body() stepData: any,
    @User() user: AuthenticatedUser
  ): Promise<void> {
    await this.workflowService.completeStep(
      tenantId,
      workflowId,
      stepId,
      stepData,
      user.id
    );
  }
}
```

### DYNAMIC FORM SYSTEM SPECIFICATION

#### **Form Schema Definition**
```typescript
interface DynamicFormSchema {
  id: string;
  name: string;
  version: string;
  fields: FormField[];
  validationRules: ValidationRule[];
  conditionalLogic: ConditionalLogic[];
  layout: FormLayout;
  styling: FormStyling;
}

interface FormField {
  id: string;
  name: string;
  type: 'text' | 'email' | 'number' | 'select' | 'multiselect' | 'checkbox' | 'radio' | 'file' | 'date' | 'textarea';
  label: string;
  placeholder?: string;
  required: boolean;
  validation: FieldValidation;
  options?: FormFieldOption[];
  dependencies: string[];
  conditionalVisibility: ConditionalRule[];
}

interface ConditionalLogic {
  condition: {
    field: string;
    operator: 'equals' | 'not_equals' | 'contains' | 'greater_than' | 'less_than';
    value: any;
  };
  actions: {
    type: 'show' | 'hide' | 'require' | 'set_value';
    target: string;
    value?: any;
  }[];
}
```

#### **Form Builder Component**
```typescript
// Dynamic Form Builder React Component
export const DynamicFormBuilder: React.FC<{
  schema: DynamicFormSchema;
  initialData?: any;
  onSubmit: (data: any) => Promise<void>;
  onStepComplete?: (step: string) => void;
}> = ({ schema, initialData, onSubmit, onStepComplete }) => {
  const [formData, setFormData] = useState(initialData || {});
  const [validationErrors, setValidationErrors] = useState({});
  const [visibleFields, setVisibleFields] = useState<Set<string>>(new Set());

  // Evaluate conditional logic
  const evaluateConditionalLogic = useCallback(() => {
    const visible = new Set<string>();
    
    schema.fields.forEach(field => {
      let isVisible = true;
      
      field.conditionalVisibility.forEach(rule => {
        const fieldValue = formData[rule.condition.field];
        const conditionMet = evaluateCondition(
          fieldValue, 
          rule.condition.operator, 
          rule.condition.value
        );
        
        if (!conditionMet) {
          isVisible = false;
        }
      });
      
      if (isVisible) {
        visible.add(field.id);
      }
    });
    
    setVisibleFields(visible);
  }, [formData, schema]);

  // Validate form data
  const validateForm = useCallback((): boolean => {
    const errors = {};
    
    schema.fields.forEach(field => {
      if (visibleFields.has(field.id)) {
        const value = formData[field.name];
        const fieldErrors = validateField(field, value);
        
        if (fieldErrors.length > 0) {
          errors[field.name] = fieldErrors;
        }
      }
    });
    
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  }, [formData, visibleFields, schema]);

  // Render form field
  const renderField = (field: FormField) => {
    if (!visibleFields.has(field.id)) return null;
    
    const fieldProps = {
      key: field.id,
      field,
      value: formData[field.name] || '',
      error: validationErrors[field.name],
      onChange: (value: any) => {
        setFormData(prev => ({
          ...prev,
          [field.name]: value
        }));
      }
    };
    
    switch (field.type) {
      case 'text':
      case 'email':
        return <TextFieldComponent {...fieldProps} />;
      case 'select':
        return <SelectFieldComponent {...fieldProps} />;
      case 'checkbox':
        return <CheckboxFieldComponent {...fieldProps} />;
      case 'file':
        return <FileUploadComponent {...fieldProps} />;
      default:
        return <TextFieldComponent {...fieldProps} />;
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-fields">
        {schema.fields.map(renderField)}
      </div>
      
      <div className="form-actions">
        <Button 
          type="submit" 
          variant="primary"
          disabled={!validateForm()}
        >
          {schema.submitLabel || 'Submit'}
        </Button>
      </div>
    </form>
  );
};
```

### INTEGRATION SPECIFICATIONS

#### **CRM Integration (Salesforce/HubSpot)**
```typescript
interface CRMIntegration {
  // Sync customer data
  syncCustomer(tenantId: string, customerId: string): Promise<void>;
  
  // Create opportunity
  createOpportunity(tenantId: string, opportunityData: any): Promise<string>;
  
  // Update deal stage
  updateDealStage(tenantId: string, dealId: string, stage: string): Promise<void>;
  
  // Log activity
  logActivity(tenantId: string, activityData: any): Promise<void>;
}

class SalesforceIntegration implements CRMIntegration {
  constructor(private apiClient: SalesforceClient) {}
  
  async syncCustomer(tenantId: string, customerId: string): Promise<void> {
    const customer = await this.getCustomerProfile(tenantId, customerId);
    
    const salesforceContact = {
      Email: customer.email,
      FirstName: customer.firstName,
      LastName: customer.lastName,
      Company: customer.companyName,
      Phone: customer.phone,
      Custom_Tenant_ID__c: tenantId,
      Custom_Customer_ID__c: customerId,
      Onboarding_Status__c: customer.onboardingStatus,
      Industry: customer.industry,
      Company_Size__c: customer.companySize
    };
    
    await this.apiClient.upsertContact(salesforceContact);
  }
}
```

#### **Email Communication Integration**
```typescript
interface EmailService {
  sendTemplatedEmail(
    tenantId: string,
    templateId: string,
    recipient: string,
    variables: Record<string, any>,
    options?: EmailOptions
  ): Promise<string>;
  
  createEmailTemplate(
    tenantId: string,
    template: EmailTemplate
  ): Promise<string>;
  
  trackEmailEvents(
    tenantId: string,
    messageId: string
  ): Promise<EmailEvent[]>;
}

class SendGridEmailService implements EmailService {
  constructor(private sendGridClient: SendGridClient) {}
  
  async sendTemplatedEmail(
    tenantId: string,
    templateId: string,
    recipient: string,
    variables: Record<string, any>,
    options?: EmailOptions
  ): Promise<string> {
    // Get tenant branding/white-labeling
    const branding = await this.getBrandingConfig(tenantId);
    
    // Apply white-labeling to email
    const personalizations = [{
      to: [{ email: recipient }],
      dynamic_template_data: {
        ...variables,
        brandLogo: branding.logoUrl,
        brandColor: branding.primaryColor,
        companyName: branding.companyName,
        supportEmail: branding.supportEmail
      }
    }];
    
    const message = {
      personalizations,
      template_id: templateId,
      from: {
        email: branding.fromEmail,
        name: branding.fromName
      },
      reply_to: {
        email: branding.replyToEmail
      }
    };
    
    const response = await this.sendGridClient.send(message);
    return response.messageId;
  }
}
```

### ANALYTICS AND MONITORING SPECIFICATION

#### **Analytics Events Schema**
```typescript
interface OnboardingAnalyticsEvent {
  tenantId: string;
  workflowId: string;
  eventType: 'workflow_started' | 'step_completed' | 'step_failed' | 
           'form_submitted' | 'email_sent' | 'email_opened' | 
           'help_accessed' | 'workflow_completed' | 'workflow_abandoned';
  eventCategory: 'workflow' | 'form' | 'communication' | 'help' | 'error';
  properties: {
    stepId?: string;
    formId?: string;
    templateId?: string;
    errorType?: string;
    duration?: number;
    completionRate?: number;
    customerId: string;
    userId?: string;
  };
  userProperties: {
    industry?: string;
    companySize?: string;
    useCase?: string;
    source?: string;
  };
  timestamp: Date;
  sessionId: string;
}
```

#### **Analytics Dashboard Queries**
```sql
-- Onboarding funnel analysis
WITH funnel_steps AS (
  SELECT 
    tenant_id,
    workflow_id,
    event_type,
    ROW_NUMBER() OVER (PARTITION BY workflow_id ORDER BY timestamp) as step_order
  FROM onboarding_analytics 
  WHERE event_category = 'workflow'
  AND timestamp >= NOW() - INTERVAL '30 days'
),
funnel_analysis AS (
  SELECT 
    tenant_id,
    event_type,
    COUNT(DISTINCT workflow_id) as unique_workflows,
    AVG(step_order) as avg_step_order
  FROM funnel_steps
  GROUP BY tenant_id, event_type
)
SELECT * FROM funnel_analysis;

-- Completion rates by template
SELECT 
  wt.name as template_name,
  COUNT(DISTINCT ow.id) as total_workflows,
  COUNT(DISTINCT CASE WHEN ow.status = 'completed' THEN ow.id END) as completed_workflows,
  ROUND(
    100.0 * COUNT(DISTINCT CASE WHEN ow.status = 'completed' THEN ow.id END) / 
    COUNT(DISTINCT ow.id), 
    2
  ) as completion_rate,
  AVG(
    CASE WHEN ow.status = 'completed' 
    THEN EXTRACT(EPOCH FROM (ow.completed_at - ow.created_at))/3600 
    END
  ) as avg_completion_hours
FROM onboarding_workflows ow
JOIN workflow_templates wt ON ow.template_id = wt.id
WHERE ow.created_at >= NOW() - INTERVAL '30 days'
GROUP BY wt.id, wt.name
ORDER BY completion_rate DESC;

-- Drop-off analysis by step
SELECT 
  ws.step_name,
  ws.step_order,
  COUNT(*) as step_starts,
  COUNT(CASE WHEN ws.status = 'completed' THEN 1 END) as step_completions,
  COUNT(CASE WHEN ws.status = 'failed' THEN 1 END) as step_failures,
  ROUND(
    100.0 * COUNT(CASE WHEN ws.status = 'completed' THEN 1 END) / COUNT(*),
    2
  ) as step_completion_rate
FROM workflow_steps ws
JOIN onboarding_workflows ow ON ws.workflow_id = ow.id
WHERE ow.created_at >= NOW() - INTERVAL '30 days'
GROUP BY ws.step_name, ws.step_order
ORDER BY step_order;
```

### SECURITY IMPLEMENTATION SPECIFICATION

#### **Data Encryption**
```typescript
// Field-level encryption for sensitive data
class DataEncryption {
  private encryptionKeys: Map<string, string> = new Map();
  
  async encryptSensitiveData(
    tenantId: string, 
    data: any, 
    sensitiveFields: string[]
  ): Promise<any> {
    const encryptionKey = await this.getTenantEncryptionKey(tenantId);
    const encrypted = { ...data };
    
    for (const field of sensitiveFields) {
      if (encrypted[field]) {
        encrypted[field] = await this.encryptField(
          encrypted[field], 
          encryptionKey
        );
      }
    }
    
    return encrypted;
  }
  
  async decryptSensitiveData(
    tenantId: string, 
    data: any, 
    sensitiveFields: string[]
  ): Promise<any> {
    const encryptionKey = await this.getTenantEncryptionKey(tenantId);
    const decrypted = { ...data };
    
    for (const field of sensitiveFields) {
      if (decrypted[field]) {
        decrypted[field] = await this.decryptField(
          decrypted[field], 
          encryptionKey
        );
      }
    }
    
    return decrypted;
  }
}
```

#### **Access Control Implementation**
```typescript
// Role-based access control for onboarding
enum OnboardingPermission {
  VIEW_WORKFLOWS = 'onboarding:view_workflows',
  MANAGE_WORKFLOWS = 'onboarding:manage_workflows',
  VIEW_ANALYTICS = 'onboarding:view_analytics',
  MANAGE_TEMPLATES = 'onboarding:manage_templates',
  VIEW_CUSTOMER_DATA = 'onboarding:view_customer_data',
  MANAGE_INTEGRATIONS = 'onboarding:manage_integrations'
}

@Injectable()
export class OnboardingAuthorizationService {
  async checkPermission(
    user: AuthenticatedUser,
    permission: OnboardingPermission,
    resourceId?: string
  ): Promise<boolean> {
    // Check user's role permissions
    const userPermissions = await this.getUserPermissions(user.id);
    
    if (!userPermissions.includes(permission)) {
      return false;
    }
    
    // Check resource-level access if resourceId provided
    if (resourceId) {
      return await this.checkResourceAccess(user, permission, resourceId);
    }
    
    return true;
  }
}
```

### TESTING FRAMEWORK SPECIFICATION

#### **End-to-End Test Suite**
```typescript
// Playwright E2E tests for onboarding flows
describe('Customer Onboarding E2E Tests', () => {
  test('Complete enterprise customer onboarding flow', async ({ page }) => {
    // Setup test customer data
    const testCustomer = await createTestCustomer({
      industry: 'financial-services',
      companySize: 'enterprise',
      complianceRequirements: ['SOC2', 'PCI-DSS']
    });
    
    // Start onboarding
    await page.goto(`/onboarding/start?customerId=${testCustomer.id}`);
    
    // Step 1: Welcome and profile
    await page.fill('[data-testid=company-name]', testCustomer.companyName);
    await page.selectOption('[data-testid=industry]', testCustomer.industry);
    await page.click('[data-testid=next-step]');
    
    // Step 2: Service selection
    await page.check('[data-testid=service-threat-detection]');
    await page.check('[data-testid=service-vulnerability-management]');
    await page.click('[data-testid=next-step]');
    
    // Step 3: Compliance requirements
    await page.check('[data-testid=compliance-soc2]');
    await page.check('[data-testid=compliance-pci-dss]');
    await page.click('[data-testid=next-step]');
    
    // Step 4: Technical setup
    await page.fill('[data-testid=domain-name]', 'test.example.com');
    await page.selectOption('[data-testid=data-region]', 'us-east-1');
    await page.click('[data-testid=next-step]');
    
    // Verify completion
    await expect(page.locator('[data-testid=onboarding-complete]')).toBeVisible();
    
    // Verify backend state
    const workflow = await getWorkflowByCustomerId(testCustomer.id);
    expect(workflow.status).toBe('completed');
    expect(workflow.steps.every(step => step.status === 'completed')).toBe(true);
  });
  
  test('Handle form validation errors gracefully', async ({ page }) => {
    await page.goto('/onboarding/start');
    
    // Submit without required fields
    await page.click('[data-testid=next-step]');
    
    // Verify error messages appear
    await expect(page.locator('[data-testid=error-company-name]')).toBeVisible();
    await expect(page.locator('[data-testid=error-industry]')).toBeVisible();
    
    // Fill required fields and continue
    await page.fill('[data-testid=company-name]', 'Test Company');
    await page.selectOption('[data-testid=industry]', 'technology');
    await page.click('[data-testid=next-step]');
    
    // Verify successful progression
    await expect(page.locator('[data-testid=step-2]')).toBeVisible();
  });
});
```

### DEPLOYMENT SPECIFICATION

#### **Kubernetes Deployment**
```yaml
# Customer Onboarding Service Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: customer-onboarding-service
  namespace: isectech-production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: customer-onboarding
  template:
    metadata:
      labels:
        app: customer-onboarding
    spec:
      containers:
      - name: onboarding-api
        image: gcr.io/isectech/customer-onboarding:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: connection-string
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: connection-string
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: encryption-keys
              key: onboarding-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

This comprehensive technical architecture document provides the detailed specifications needed to implement the Customer Onboarding Automation system. The specialized agent should use this as a reference for all technical implementation decisions while following the business requirements outlined in the main instructions document.