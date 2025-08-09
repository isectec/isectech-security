/**
 * iSECTECH POC Signup Portal - Production-Grade Implementation
 * Self-Service POC Registration and Onboarding System
 * Version: 1.0
 * Author: Claude Code Implementation
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle,
  Button,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Checkbox,
  Textarea,
  Alert,
  AlertDescription,
  Progress,
  Badge,
  Separator,
  RadioGroup,
  RadioGroupItem
} from '@/components/ui';
import { 
  Shield, 
  Building2, 
  Users, 
  Globe, 
  CheckCircle, 
  Clock, 
  ArrowRight, 
  ArrowLeft,
  Info,
  Lock,
  Mail,
  Phone,
  MapPin,
  Briefcase
} from 'lucide-react';
import { useForm, useFieldArray } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { toast } from 'sonner';

// Enhanced validation schema for POC signup
const pocSignupSchema = z.object({
  // Company Information
  companyInfo: z.object({
    companyName: z.string().min(2, 'Company name must be at least 2 characters').max(100),
    industryVertical: z.enum([
      'financial_services', 'healthcare', 'government', 'education',
      'retail', 'manufacturing', 'technology', 'energy', 'telecommunications',
      'media_entertainment', 'transportation', 'real_estate', 'other'
    ]),
    companySize: z.enum(['startup', 'small', 'medium', 'large', 'enterprise']),
    employeeCount: z.number().min(1).max(1000000),
    annualRevenue: z.string().optional(),
    websiteUrl: z.string().url().optional().or(z.literal('')),
    headquartersCountry: z.string().min(2).max(2),
    description: z.string().max(500).optional(),
  }),

  // Primary Contact Information
  primaryContact: z.object({
    firstName: z.string().min(2, 'First name is required').max(50),
    lastName: z.string().min(2, 'Last name is required').max(50),
    email: z.string().email('Please enter a valid email address'),
    phone: z.string().min(10, 'Please enter a valid phone number').optional(),
    jobTitle: z.string().min(2, 'Job title is required').max(100),
    department: z.string().max(50).optional(),
  }),

  // POC Requirements
  pocRequirements: z.object({
    pocTier: z.enum(['standard', 'enterprise', 'premium']),
    durationDays: z.number().min(7).max(180),
    expectedUsers: z.number().min(1).max(500),
    primaryUseCase: z.string().min(10, 'Please describe your primary use case').max(500),
    evaluationObjectives: z.array(z.string()).min(1, 'Please select at least one objective'),
    successCriteria: z.string().min(10, 'Please describe your success criteria').max(500),
    currentSecurityTools: z.array(z.string()),
    integrationRequirements: z.string().max(500).optional(),
  }),

  // Security and Compliance
  securityRequirements: z.object({
    securityClearance: z.enum(['unclassified', 'confidential', 'secret', 'top_secret']),
    dataResidencyRegion: z.enum(['us', 'eu', 'uk', 'ca', 'au', 'jp', 'in', 'sg', 'global']),
    complianceFrameworks: z.array(z.string()).min(1, 'Please select at least one framework'),
    hasSensitiveData: z.boolean(),
    dataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']).optional(),
  }),

  // Business Context
  businessContext: z.object({
    budgetRange: z.string(),
    timelineToDecision: z.string(),
    decisionMakers: z.array(z.object({
      name: z.string().min(2).max(100),
      title: z.string().min(2).max(100),
      email: z.string().email(),
      role: z.enum(['decision_maker', 'influencer', 'champion', 'user'])
    })).min(1, 'Please add at least one decision maker'),
    competitiveAlternatives: z.array(z.string()),
    primaryChallenges: z.array(z.string()).min(1, 'Please select primary challenges'),
  }),

  // Legal and Agreements
  legal: z.object({
    termsAccepted: z.boolean().refine(val => val === true, 'You must accept the terms'),
    privacyPolicyAccepted: z.boolean().refine(val => val === true, 'You must accept the privacy policy'),
    dataProcessingConsent: z.boolean().refine(val => val === true, 'Data processing consent is required'),
    marketingConsent: z.boolean().optional(),
    nda: z.object({
      required: z.boolean(),
      accepted: z.boolean().optional(),
      documentUrl: z.string().optional(),
    }),
  }),
});

type POCSignupForm = z.infer<typeof pocSignupSchema>;

// Configuration constants
const INDUSTRY_VERTICALS = [
  { value: 'financial_services', label: 'Financial Services', icon: '🏦' },
  { value: 'healthcare', label: 'Healthcare', icon: '🏥' },
  { value: 'government', label: 'Government', icon: '🏛️' },
  { value: 'education', label: 'Education', icon: '🎓' },
  { value: 'retail', label: 'Retail', icon: '🛍️' },
  { value: 'manufacturing', label: 'Manufacturing', icon: '🏭' },
  { value: 'technology', label: 'Technology', icon: '💻' },
  { value: 'energy', label: 'Energy', icon: '⚡' },
  { value: 'telecommunications', label: 'Telecommunications', icon: '📡' },
  { value: 'media_entertainment', label: 'Media & Entertainment', icon: '🎬' },
  { value: 'transportation', label: 'Transportation', icon: '🚛' },
  { value: 'real_estate', label: 'Real Estate', icon: '🏢' },
  { value: 'other', label: 'Other', icon: '🔧' },
];

const COMPANY_SIZES = [
  { value: 'startup', label: 'Startup (1-10 employees)', description: 'Early stage company' },
  { value: 'small', label: 'Small (11-50 employees)', description: 'Small business' },
  { value: 'medium', label: 'Medium (51-200 employees)', description: 'Mid-market company' },
  { value: 'large', label: 'Large (201-1000 employees)', description: 'Large enterprise' },
  { value: 'enterprise', label: 'Enterprise (1000+ employees)', description: 'Global enterprise' },
];

const POC_TIERS = [
  {
    value: 'standard',
    label: 'Standard POC',
    description: 'Core security features with basic analytics',
    features: ['Threat Detection', 'Vulnerability Scanning', 'Compliance Reporting', 'Basic SIEM'],
    resources: '8 CPU cores, 32GB RAM, 25 users',
    duration: 'Up to 30 days',
    price: 'Free',
    recommended: false,
  },
  {
    value: 'enterprise',
    label: 'Enterprise POC',
    description: 'Advanced features with AI/ML analytics',
    features: ['All Standard Features', 'AI/ML Analytics', 'SOAR Automation', 'Custom Integrations'],
    resources: '16 CPU cores, 64GB RAM, 100 users',
    duration: 'Up to 90 days',
    price: 'Contact Sales',
    recommended: true,
  },
  {
    value: 'premium',
    label: 'Premium POC',
    description: 'Full platform access with dedicated support',
    features: ['All Enterprise Features', 'White Labeling', 'Dedicated Support', 'Custom Connectors'],
    resources: '32 CPU cores, 128GB RAM, 500 users',
    duration: 'Up to 180 days',
    price: 'Contact Sales',
    recommended: false,
  },
];

const COMPLIANCE_FRAMEWORKS = [
  { value: 'soc2', label: 'SOC 2 Type II', description: 'Service Organization Control 2' },
  { value: 'iso27001', label: 'ISO 27001', description: 'Information Security Management' },
  { value: 'hipaa', label: 'HIPAA', description: 'Healthcare Information Privacy' },
  { value: 'gdpr', label: 'GDPR', description: 'EU General Data Protection Regulation' },
  { value: 'fedramp', label: 'FedRAMP', description: 'Federal Risk and Authorization Management' },
  { value: 'fisma', label: 'FISMA', description: 'Federal Information Security Management' },
  { value: 'pci_dss', label: 'PCI DSS', description: 'Payment Card Industry Data Security' },
  { value: 'ccpa', label: 'CCPA', description: 'California Consumer Privacy Act' },
  { value: 'nist', label: 'NIST CSF', description: 'NIST Cybersecurity Framework' },
  { value: 'cis', label: 'CIS Controls', description: 'Center for Internet Security Controls' },
];

const SECURITY_TOOLS = [
  'Splunk', 'QRadar', 'Sentinel', 'ElasticSearch', 'Sumo Logic',
  'CrowdStrike', 'SentinelOne', 'Carbon Black', 'Cylance', 'Symantec',
  'Okta', 'Active Directory', 'Ping Identity', 'Auth0', 'Azure AD',
  'AWS Security Hub', 'Azure Security Center', 'GCP Security Command Center',
  'Palo Alto', 'Fortinet', 'Cisco', 'Check Point', 'Zscaler'
];

const EVALUATION_OBJECTIVES = [
  'Improve threat detection capabilities',
  'Reduce false positive rates',
  'Enhance incident response times',
  'Achieve compliance requirements',
  'Consolidate security tools',
  'Improve SOC efficiency',
  'Enable automated response',
  'Better visibility and reporting',
  'Cost reduction and optimization',
  'Skill gap mitigation through automation'
];

const PRIMARY_CHALLENGES = [
  'Alert fatigue and false positives',
  'Lack of skilled security personnel',
  'Complex compliance requirements',
  'Fragmented security tools',
  'Slow incident response',
  'Limited visibility across environment',
  'High operational costs',
  'Difficulty scaling security operations',
  'Integration and interoperability issues',
  'Keeping up with evolving threats'
];

// Step configuration
const SIGNUP_STEPS = [
  { id: 1, title: 'Company Information', icon: Building2, description: 'Tell us about your organization' },
  { id: 2, title: 'Contact Details', icon: Users, description: 'Primary contact information' },
  { id: 3, title: 'POC Requirements', icon: Shield, description: 'Define your evaluation needs' },
  { id: 4, title: 'Security & Compliance', icon: Lock, description: 'Security and compliance requirements' },
  { id: 5, title: 'Business Context', icon: Briefcase, description: 'Decision process and timeline' },
  { id: 6, title: 'Legal & Agreements', icon: CheckCircle, description: 'Terms and legal agreements' },
];

interface POCSignupPortalProps {
  onSubmit?: (data: POCSignupForm) => Promise<void>;
  onCancel?: () => void;
  initialData?: Partial<POCSignupForm>;
  readonly?: boolean;
}

export const POCSignupPortal: React.FC<POCSignupPortalProps> = ({
  onSubmit,
  onCancel,
  initialData,
  readonly = false
}) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [estimatedSetupTime, setEstimatedSetupTime] = useState('2-4 hours');

  const form = useForm<POCSignupForm>({
    resolver: zodResolver(pocSignupSchema),
    defaultValues: {
      companyInfo: {
        industryVertical: 'technology',
        companySize: 'medium',
        headquartersCountry: 'US',
        ...initialData?.companyInfo,
      },
      pocRequirements: {
        pocTier: 'enterprise',
        durationDays: 30,
        expectedUsers: 10,
        evaluationObjectives: [],
        currentSecurityTools: [],
        ...initialData?.pocRequirements,
      },
      securityRequirements: {
        securityClearance: 'unclassified',
        dataResidencyRegion: 'us',
        complianceFrameworks: ['soc2'],
        hasSensitiveData: false,
        ...initialData?.securityRequirements,
      },
      businessContext: {
        budgetRange: '100k-500k',
        timelineToDecision: '3-6 months',
        decisionMakers: [],
        competitiveAlternatives: [],
        primaryChallenges: [],
        ...initialData?.businessContext,
      },
      legal: {
        termsAccepted: false,
        privacyPolicyAccepted: false,
        dataProcessingConsent: false,
        marketingConsent: false,
        nda: {
          required: false,
          accepted: false,
        },
        ...initialData?.legal,
      },
      ...initialData,
    },
  });

  const { fields: decisionMakersFields, append: appendDecisionMaker, remove: removeDecisionMaker } = useFieldArray({
    control: form.control,
    name: 'businessContext.decisionMakers',
  });

  // Watch form values for dynamic updates
  const watchedValues = form.watch();
  const pocTier = form.watch('pocRequirements.pocTier');
  const companySize = form.watch('companyInfo.companySize');
  const industryVertical = form.watch('companyInfo.industryVertical');

  // Dynamic setup time estimation
  useEffect(() => {
    const calculateSetupTime = () => {
      let baseTime = 2; // hours
      
      if (pocTier === 'enterprise') baseTime += 1;
      if (pocTier === 'premium') baseTime += 2;
      if (companySize === 'enterprise') baseTime += 1;
      if (watchedValues.securityRequirements?.complianceFrameworks?.length > 2) baseTime += 1;
      if (watchedValues.pocRequirements?.integrationRequirements) baseTime += 1;
      
      return `${baseTime}-${baseTime + 2} hours`;
    };
    
    setEstimatedSetupTime(calculateSetupTime());
  }, [pocTier, companySize, watchedValues]);

  const handleStepChange = useCallback((step: number) => {
    setCurrentStep(step);
  }, []);

  const handleNext = useCallback(async () => {
    const stepFields = getStepFields(currentStep);
    const isValid = await form.trigger(stepFields as any);
    
    if (isValid) {
      setCurrentStep(prev => Math.min(prev + 1, SIGNUP_STEPS.length));
    } else {
      toast.error('Please correct the errors before proceeding');
    }
  }, [currentStep, form]);

  const handlePrevious = useCallback(() => {
    setCurrentStep(prev => Math.max(prev - 1, 1));
  }, []);

  const handleSubmit = useCallback(async (data: POCSignupForm) => {
    setIsLoading(true);
    try {
      await onSubmit?.(data);
      toast.success('POC request submitted successfully! You will receive a confirmation email shortly.');
    } catch (error) {
      toast.error('Failed to submit POC request. Please try again.');
      console.error('Signup submission error:', error);
    } finally {
      setIsLoading(false);
    }
  }, [onSubmit]);

  const getStepFields = (step: number): string[] => {
    switch (step) {
      case 1: return ['companyInfo'];
      case 2: return ['primaryContact'];
      case 3: return ['pocRequirements'];
      case 4: return ['securityRequirements'];
      case 5: return ['businessContext'];
      case 6: return ['legal'];
      default: return [];
    }
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return <CompanyInformationStep form={form} readonly={readonly} />;
      case 2:
        return <ContactDetailsStep form={form} readonly={readonly} />;
      case 3:
        return <POCRequirementsStep form={form} readonly={readonly} />;
      case 4:
        return <SecurityComplianceStep form={form} readonly={readonly} />;
      case 5:
        return (
          <BusinessContextStep 
            form={form} 
            readonly={readonly}
            decisionMakersFields={decisionMakersFields}
            appendDecisionMaker={appendDecisionMaker}
            removeDecisionMaker={removeDecisionMaker}
          />
        );
      case 6:
        return <LegalAgreementsStep form={form} readonly={readonly} />;
      default:
        return null;
    }
  };

  const progress = (currentStep / SIGNUP_STEPS.length) * 100;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 py-8">
      <div className="container mx-auto px-4 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-600 mr-3" />
            <h1 className="text-4xl font-bold text-gray-900">iSECTECH POC Portal</h1>
          </div>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Start your cybersecurity evaluation journey with a tailored proof of concept environment
          </p>
          <div className="mt-4 flex items-center justify-center space-x-6 text-sm text-gray-500">
            <div className="flex items-center">
              <Clock className="h-4 w-4 mr-1" />
              Setup time: {estimatedSetupTime}
            </div>
            <div className="flex items-center">
              <CheckCircle className="h-4 w-4 mr-1" />
              Production-grade environment
            </div>
            <div className="flex items-center">
              <Shield className="h-4 w-4 mr-1" />
              Enterprise security
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <Card className="mb-8">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium text-gray-700">
                Step {currentStep} of {SIGNUP_STEPS.length}
              </span>
              <span className="text-sm text-gray-500">{Math.round(progress)}% Complete</span>
            </div>
            <Progress value={progress} className="mb-4" />
            <div className="flex justify-between">
              {SIGNUP_STEPS.map((step, index) => {
                const StepIcon = step.icon;
                const isActive = currentStep === step.id;
                const isCompleted = currentStep > step.id;
                
                return (
                  <div
                    key={step.id}
                    className={`flex flex-col items-center cursor-pointer transition-colors ${
                      isActive ? 'text-blue-600' : isCompleted ? 'text-green-600' : 'text-gray-400'
                    }`}
                    onClick={() => !readonly && handleStepChange(step.id)}
                  >
                    <div className={`p-2 rounded-full border-2 transition-colors ${
                      isActive ? 'border-blue-600 bg-blue-50' : 
                      isCompleted ? 'border-green-600 bg-green-50' : 'border-gray-300'
                    }`}>
                      {isCompleted ? (
                        <CheckCircle className="h-5 w-5" />
                      ) : (
                        <StepIcon className="h-5 w-5" />
                      )}
                    </div>
                    <span className="text-xs mt-1 text-center max-w-20">{step.title}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Main Form */}
        <form onSubmit={form.handleSubmit(handleSubmit)}>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                {React.createElement(SIGNUP_STEPS[currentStep - 1].icon, { className: "h-6 w-6 mr-2" })}
                {SIGNUP_STEPS[currentStep - 1].title}
              </CardTitle>
              <p className="text-gray-600">{SIGNUP_STEPS[currentStep - 1].description}</p>
            </CardHeader>
            <CardContent>
              {renderStepContent()}
            </CardContent>
          </Card>

          {/* Navigation Buttons */}
          <div className="flex justify-between mt-8">
            <Button
              type="button"
              variant="outline"
              onClick={currentStep === 1 ? onCancel : handlePrevious}
              disabled={isLoading}
              className="flex items-center"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              {currentStep === 1 ? 'Cancel' : 'Previous'}
            </Button>
            
            {currentStep < SIGNUP_STEPS.length ? (
              <Button
                type="button"
                onClick={handleNext}
                disabled={isLoading || readonly}
                className="flex items-center"
              >
                Next
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            ) : (
              <Button
                type="submit"
                disabled={isLoading || readonly}
                className="flex items-center bg-blue-600 hover:bg-blue-700"
              >
                {isLoading ? 'Submitting...' : 'Submit POC Request'}
                <CheckCircle className="h-4 w-4 ml-2" />
              </Button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};

// Step Components
const CompanyInformationStep: React.FC<{ form: any; readonly: boolean }> = ({ form, readonly }) => (
  <div className="space-y-6">
    <Alert>
      <Info className="h-4 w-4" />
      <AlertDescription>
        This information helps us customize your POC environment and provide relevant security scenarios.
      </AlertDescription>
    </Alert>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="space-y-2">
        <Label htmlFor="companyName">Company Name *</Label>
        <Input
          id="companyName"
          {...form.register('companyInfo.companyName')}
          placeholder="Enter your company name"
          disabled={readonly}
        />
        {form.formState.errors.companyInfo?.companyName && (
          <p className="text-sm text-red-600">{form.formState.errors.companyInfo.companyName.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="industryVertical">Industry Vertical *</Label>
        <Select onValueChange={(value) => form.setValue('companyInfo.industryVertical', value)} disabled={readonly}>
          <SelectTrigger>
            <SelectValue placeholder="Select your industry" />
          </SelectTrigger>
          <SelectContent>
            {INDUSTRY_VERTICALS.map((industry) => (
              <SelectItem key={industry.value} value={industry.value}>
                <span className="flex items-center">
                  <span className="mr-2">{industry.icon}</span>
                  {industry.label}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="companySize">Company Size *</Label>
        <Select onValueChange={(value) => form.setValue('companyInfo.companySize', value)} disabled={readonly}>
          <SelectTrigger>
            <SelectValue placeholder="Select company size" />
          </SelectTrigger>
          <SelectContent>
            {COMPANY_SIZES.map((size) => (
              <SelectItem key={size.value} value={size.value}>
                <div className="flex flex-col">
                  <span>{size.label}</span>
                  <span className="text-xs text-gray-500">{size.description}</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="employeeCount">Employee Count</Label>
        <Input
          id="employeeCount"
          type="number"
          {...form.register('companyInfo.employeeCount', { valueAsNumber: true })}
          placeholder="Number of employees"
          disabled={readonly}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="websiteUrl">Website URL</Label>
        <Input
          id="websiteUrl"
          {...form.register('companyInfo.websiteUrl')}
          placeholder="https://yourcompany.com"
          disabled={readonly}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="headquartersCountry">Headquarters Country *</Label>
        <Select onValueChange={(value) => form.setValue('companyInfo.headquartersCountry', value)} disabled={readonly}>
          <SelectTrigger>
            <SelectValue placeholder="Select country" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="US">🇺🇸 United States</SelectItem>
            <SelectItem value="CA">🇨🇦 Canada</SelectItem>
            <SelectItem value="GB">🇬🇧 United Kingdom</SelectItem>
            <SelectItem value="DE">🇩🇪 Germany</SelectItem>
            <SelectItem value="FR">🇫🇷 France</SelectItem>
            <SelectItem value="AU">🇦🇺 Australia</SelectItem>
            <SelectItem value="JP">🇯🇵 Japan</SelectItem>
            <SelectItem value="IN">🇮🇳 India</SelectItem>
            <SelectItem value="SG">🇸🇬 Singapore</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>

    <div className="space-y-2">
      <Label htmlFor="description">Company Description (Optional)</Label>
      <Textarea
        id="description"
        {...form.register('companyInfo.description')}
        placeholder="Brief description of your company and business"
        maxLength={500}
        disabled={readonly}
        rows={3}
      />
    </div>
  </div>
);

const ContactDetailsStep: React.FC<{ form: any; readonly: boolean }> = ({ form, readonly }) => (
  <div className="space-y-6">
    <Alert>
      <Users className="h-4 w-4" />
      <AlertDescription>
        We'll use this information to set up your POC environment and provide personalized support.
      </AlertDescription>
    </Alert>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="space-y-2">
        <Label htmlFor="firstName">First Name *</Label>
        <Input
          id="firstName"
          {...form.register('primaryContact.firstName')}
          placeholder="Enter your first name"
          disabled={readonly}
        />
        {form.formState.errors.primaryContact?.firstName && (
          <p className="text-sm text-red-600">{form.formState.errors.primaryContact.firstName.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="lastName">Last Name *</Label>
        <Input
          id="lastName"
          {...form.register('primaryContact.lastName')}
          placeholder="Enter your last name"
          disabled={readonly}
        />
        {form.formState.errors.primaryContact?.lastName && (
          <p className="text-sm text-red-600">{form.formState.errors.primaryContact.lastName.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="email">Business Email *</Label>
        <div className="relative">
          <Mail className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
          <Input
            id="email"
            type="email"
            {...form.register('primaryContact.email')}
            placeholder="your.email@company.com"
            className="pl-10"
            disabled={readonly}
          />
        </div>
        {form.formState.errors.primaryContact?.email && (
          <p className="text-sm text-red-600">{form.formState.errors.primaryContact.email.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="phone">Phone Number</Label>
        <div className="relative">
          <Phone className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
          <Input
            id="phone"
            {...form.register('primaryContact.phone')}
            placeholder="+1 (555) 123-4567"
            className="pl-10"
            disabled={readonly}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="jobTitle">Job Title *</Label>
        <Input
          id="jobTitle"
          {...form.register('primaryContact.jobTitle')}
          placeholder="e.g., CISO, Security Architect, IT Director"
          disabled={readonly}
        />
        {form.formState.errors.primaryContact?.jobTitle && (
          <p className="text-sm text-red-600">{form.formState.errors.primaryContact.jobTitle.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="department">Department</Label>
        <Input
          id="department"
          {...form.register('primaryContact.department')}
          placeholder="e.g., Information Security, IT Operations"
          disabled={readonly}
        />
      </div>
    </div>
  </div>
);

const POCRequirementsStep: React.FC<{ form: any; readonly: boolean }> = ({ form, readonly }) => (
  <div className="space-y-6">
    <Alert>
      <Shield className="h-4 w-4" />
      <AlertDescription>
        Configure your POC environment based on your evaluation requirements and expected usage.
      </AlertDescription>
    </Alert>

    {/* POC Tier Selection */}
    <div className="space-y-4">
      <Label>POC Tier Selection *</Label>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {POC_TIERS.map((tier) => (
          <Card
            key={tier.value}
            className={`cursor-pointer transition-all border-2 ${
              form.watch('pocRequirements.pocTier') === tier.value
                ? 'border-blue-500 ring-2 ring-blue-200'
                : 'border-gray-200 hover:border-gray-300'
            } ${tier.recommended ? 'ring-2 ring-green-200 border-green-300' : ''}`}
            onClick={() => !readonly && form.setValue('pocRequirements.pocTier', tier.value)}
          >
            <CardContent className="p-4">
              <div className="flex items-start justify-between mb-2">
                <h3 className="font-semibold text-lg">{tier.label}</h3>
                {tier.recommended && (
                  <Badge variant="secondary" className="bg-green-100 text-green-800">
                    Recommended
                  </Badge>
                )}
              </div>
              <p className="text-sm text-gray-600 mb-3">{tier.description}</p>
              <div className="space-y-2 text-sm">
                <div><strong>Resources:</strong> {tier.resources}</div>
                <div><strong>Duration:</strong> {tier.duration}</div>
                <div><strong>Price:</strong> {tier.price}</div>
              </div>
              <div className="mt-3">
                <div className="text-sm font-medium mb-1">Features:</div>
                <div className="flex flex-wrap gap-1">
                  {tier.features.map((feature, index) => (
                    <Badge key={index} variant="outline" className="text-xs">
                      {feature}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="space-y-2">
        <Label htmlFor="durationDays">POC Duration (Days) *</Label>
        <Input
          id="durationDays"
          type="number"
          min="7"
          max="180"
          {...form.register('pocRequirements.durationDays', { valueAsNumber: true })}
          placeholder="30"
          disabled={readonly}
        />
        <p className="text-xs text-gray-500">Duration can be extended based on evaluation progress</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="expectedUsers">Expected Number of Users *</Label>
        <Input
          id="expectedUsers"
          type="number"
          min="1"
          {...form.register('pocRequirements.expectedUsers', { valueAsNumber: true })}
          placeholder="10"
          disabled={readonly}
        />
      </div>
    </div>

    <div className="space-y-2">
      <Label htmlFor="primaryUseCase">Primary Use Case *</Label>
      <Textarea
        id="primaryUseCase"
        {...form.register('pocRequirements.primaryUseCase')}
        placeholder="Describe your primary use case for the cybersecurity platform evaluation..."
        rows={3}
        disabled={readonly}
      />
      {form.formState.errors.pocRequirements?.primaryUseCase && (
        <p className="text-sm text-red-600">{form.formState.errors.pocRequirements.primaryUseCase.message}</p>
      )}
    </div>

    <div className="space-y-4">
      <Label>Evaluation Objectives *</Label>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {EVALUATION_OBJECTIVES.map((objective) => (
          <div key={objective} className="flex items-center space-x-2">
            <Checkbox
              id={`objective-${objective}`}
              checked={form.watch('pocRequirements.evaluationObjectives')?.includes(objective)}
              onCheckedChange={(checked) => {
                const current = form.watch('pocRequirements.evaluationObjectives') || [];
                if (checked) {
                  form.setValue('pocRequirements.evaluationObjectives', [...current, objective]);
                } else {
                  form.setValue('pocRequirements.evaluationObjectives', current.filter(item => item !== objective));
                }
              }}
              disabled={readonly}
            />
            <Label htmlFor={`objective-${objective}`} className="text-sm">{objective}</Label>
          </div>
        ))}
      </div>
    </div>

    <div className="space-y-2">
      <Label htmlFor="successCriteria">Success Criteria *</Label>
      <Textarea
        id="successCriteria"
        {...form.register('pocRequirements.successCriteria')}
        placeholder="Define what success looks like for your POC evaluation..."
        rows={3}
        disabled={readonly}
      />
      {form.formState.errors.pocRequirements?.successCriteria && (
        <p className="text-sm text-red-600">{form.formState.errors.pocRequirements.successCriteria.message}</p>
      )}
    </div>

    <div className="space-y-4">
      <Label>Current Security Tools</Label>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
        {SECURITY_TOOLS.map((tool) => (
          <div key={tool} className="flex items-center space-x-2">
            <Checkbox
              id={`tool-${tool}`}
              checked={form.watch('pocRequirements.currentSecurityTools')?.includes(tool)}
              onCheckedChange={(checked) => {
                const current = form.watch('pocRequirements.currentSecurityTools') || [];
                if (checked) {
                  form.setValue('pocRequirements.currentSecurityTools', [...current, tool]);
                } else {
                  form.setValue('pocRequirements.currentSecurityTools', current.filter(item => item !== tool));
                }
              }}
              disabled={readonly}
            />
            <Label htmlFor={`tool-${tool}`} className="text-sm">{tool}</Label>
          </div>
        ))}
      </div>
    </div>

    <div className="space-y-2">
      <Label htmlFor="integrationRequirements">Integration Requirements (Optional)</Label>
      <Textarea
        id="integrationRequirements"
        {...form.register('pocRequirements.integrationRequirements')}
        placeholder="Describe any specific integration requirements or external systems to connect..."
        rows={3}
        disabled={readonly}
      />
    </div>
  </div>
);

const SecurityComplianceStep: React.FC<{ form: any; readonly: boolean }> = ({ form, readonly }) => (
  <div className="space-y-6">
    <Alert>
      <Lock className="h-4 w-4" />
      <AlertDescription>
        Security and compliance settings ensure your POC environment meets your organizational requirements.
      </AlertDescription>
    </Alert>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="space-y-2">
        <Label>Security Clearance Level *</Label>
        <RadioGroup
          value={form.watch('securityRequirements.securityClearance')}
          onValueChange={(value) => form.setValue('securityRequirements.securityClearance', value)}
          disabled={readonly}
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="unclassified" id="unclassified" />
            <Label htmlFor="unclassified">Unclassified</Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="confidential" id="confidential" />
            <Label htmlFor="confidential">Confidential</Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="secret" id="secret" />
            <Label htmlFor="secret">Secret</Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="top_secret" id="top_secret" />
            <Label htmlFor="top_secret">Top Secret</Label>
          </div>
        </RadioGroup>
      </div>

      <div className="space-y-2">
        <Label>Data Residency Region *</Label>
        <Select 
          onValueChange={(value) => form.setValue('securityRequirements.dataResidencyRegion', value)} 
          disabled={readonly}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select region" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="us">🇺🇸 United States</SelectItem>
            <SelectItem value="eu">🇪🇺 European Union</SelectItem>
            <SelectItem value="uk">🇬🇧 United Kingdom</SelectItem>
            <SelectItem value="ca">🇨🇦 Canada</SelectItem>
            <SelectItem value="au">🇦🇺 Australia</SelectItem>
            <SelectItem value="jp">🇯🇵 Japan</SelectItem>
            <SelectItem value="in">🇮🇳 India</SelectItem>
            <SelectItem value="sg">🇸🇬 Singapore</SelectItem>
            <SelectItem value="global">🌍 Global (No specific requirements)</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>

    <div className="space-y-4">
      <Label>Compliance Frameworks *</Label>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {COMPLIANCE_FRAMEWORKS.map((framework) => (
          <div key={framework.value} className="border rounded-lg p-3">
            <div className="flex items-start space-x-3">
              <Checkbox
                id={`framework-${framework.value}`}
                checked={form.watch('securityRequirements.complianceFrameworks')?.includes(framework.value)}
                onCheckedChange={(checked) => {
                  const current = form.watch('securityRequirements.complianceFrameworks') || [];
                  if (checked) {
                    form.setValue('securityRequirements.complianceFrameworks', [...current, framework.value]);
                  } else {
                    form.setValue('securityRequirements.complianceFrameworks', current.filter(item => item !== framework.value));
                  }
                }}
                disabled={readonly}
              />
              <div className="flex-1">
                <Label htmlFor={`framework-${framework.value}`} className="font-medium">
                  {framework.label}
                </Label>
                <p className="text-sm text-gray-600 mt-1">{framework.description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>

    <div className="space-y-4">
      <div className="flex items-center space-x-2">
        <Checkbox
          id="hasSensitiveData"
          checked={form.watch('securityRequirements.hasSensitiveData')}
          onCheckedChange={(checked) => form.setValue('securityRequirements.hasSensitiveData', checked)}
          disabled={readonly}
        />
        <Label htmlFor="hasSensitiveData">
          Will you be uploading or processing sensitive data during the POC?
        </Label>
      </div>

      {form.watch('securityRequirements.hasSensitiveData') && (
        <div className="ml-6 space-y-2">
          <Label>Data Classification Level</Label>
          <RadioGroup
            value={form.watch('securityRequirements.dataClassification')}
            onValueChange={(value) => form.setValue('securityRequirements.dataClassification', value)}
            disabled={readonly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="internal" id="internal" />
              <Label htmlFor="internal">Internal Use Only</Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="confidential" id="data-confidential" />
              <Label htmlFor="data-confidential">Confidential</Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="restricted" id="restricted" />
              <Label htmlFor="restricted">Restricted/Highly Sensitive</Label>
            </div>
          </RadioGroup>
        </div>
      )}
    </div>
  </div>
);

const BusinessContextStep: React.FC<{
  form: any;
  readonly: boolean;
  decisionMakersFields: any[];
  appendDecisionMaker: (value: any) => void;
  removeDecisionMaker: (index: number) => void;
}> = ({ form, readonly, decisionMakersFields, appendDecisionMaker, removeDecisionMaker }) => (
  <div className="space-y-6">
    <Alert>
      <Briefcase className="h-4 w-4" />
      <AlertDescription>
        Understanding your decision process helps us tailor the POC experience and provide relevant demonstrations.
      </AlertDescription>
    </Alert>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="space-y-2">
        <Label>Budget Range</Label>
        <Select onValueChange={(value) => form.setValue('businessContext.budgetRange', value)} disabled={readonly}>
          <SelectTrigger>
            <SelectValue placeholder="Select budget range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="under-100k">Under $100K</SelectItem>
            <SelectItem value="100k-500k">$100K - $500K</SelectItem>
            <SelectItem value="500k-1m">$500K - $1M</SelectItem>
            <SelectItem value="1m-5m">$1M - $5M</SelectItem>
            <SelectItem value="over-5m">Over $5M</SelectItem>
            <SelectItem value="not-determined">Not Yet Determined</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label>Timeline to Decision</Label>
        <Select onValueChange={(value) => form.setValue('businessContext.timelineToDecision', value)} disabled={readonly}>
          <SelectTrigger>
            <SelectValue placeholder="Select timeline" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="immediate">Immediate (within 30 days)</SelectItem>
            <SelectItem value="1-3-months">1-3 months</SelectItem>
            <SelectItem value="3-6-months">3-6 months</SelectItem>
            <SelectItem value="6-12-months">6-12 months</SelectItem>
            <SelectItem value="over-12-months">Over 12 months</SelectItem>
            <SelectItem value="exploratory">Exploratory (no set timeline)</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>

    {/* Decision Makers */}
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Label>Key Decision Makers *</Label>
        {!readonly && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => appendDecisionMaker({
              name: '',
              title: '',
              email: '',
              role: 'decision_maker'
            })}
          >
            Add Decision Maker
          </Button>
        )}
      </div>

      {decisionMakersFields.map((field, index) => (
        <Card key={field.id} className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input
                {...form.register(`businessContext.decisionMakers.${index}.name`)}
                placeholder="Full name"
                disabled={readonly}
              />
            </div>
            <div className="space-y-2">
              <Label>Title</Label>
              <Input
                {...form.register(`businessContext.decisionMakers.${index}.title`)}
                placeholder="Job title"
                disabled={readonly}
              />
            </div>
            <div className="space-y-2">
              <Label>Email</Label>
              <Input
                {...form.register(`businessContext.decisionMakers.${index}.email`)}
                type="email"
                placeholder="email@company.com"
                disabled={readonly}
              />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <div className="flex items-center justify-between">
                <Select
                  onValueChange={(value) => form.setValue(`businessContext.decisionMakers.${index}.role`, value)}
                  disabled={readonly}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="decision_maker">Decision Maker</SelectItem>
                    <SelectItem value="influencer">Influencer</SelectItem>
                    <SelectItem value="champion">Champion</SelectItem>
                    <SelectItem value="user">End User</SelectItem>
                  </SelectContent>
                </Select>
                {!readonly && decisionMakersFields.length > 1 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removeDecisionMaker(index)}
                    className="ml-2 text-red-600 hover:text-red-700"
                  >
                    Remove
                  </Button>
                )}
              </div>
            </div>
          </div>
        </Card>
      ))}
    </div>

    {/* Primary Challenges */}
    <div className="space-y-4">
      <Label>Primary Security Challenges *</Label>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {PRIMARY_CHALLENGES.map((challenge) => (
          <div key={challenge} className="flex items-center space-x-2">
            <Checkbox
              id={`challenge-${challenge}`}
              checked={form.watch('businessContext.primaryChallenges')?.includes(challenge)}
              onCheckedChange={(checked) => {
                const current = form.watch('businessContext.primaryChallenges') || [];
                if (checked) {
                  form.setValue('businessContext.primaryChallenges', [...current, challenge]);
                } else {
                  form.setValue('businessContext.primaryChallenges', current.filter(item => item !== challenge));
                }
              }}
              disabled={readonly}
            />
            <Label htmlFor={`challenge-${challenge}`} className="text-sm">{challenge}</Label>
          </div>
        ))}
      </div>
    </div>

    {/* Competitive Alternatives */}
    <div className="space-y-4">
      <Label>Competitive Alternatives Being Considered</Label>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {['Splunk', 'IBM QRadar', 'Microsoft Sentinel', 'CrowdStrike', 'Palo Alto Cortex', 'Fortinet', 'Check Point', 'Symantec', 'Rapid7', 'LogRhythm', 'McAfee', 'Trend Micro', 'Other'].map((alternative) => (
          <div key={alternative} className="flex items-center space-x-2">
            <Checkbox
              id={`alternative-${alternative}`}
              checked={form.watch('businessContext.competitiveAlternatives')?.includes(alternative)}
              onCheckedChange={(checked) => {
                const current = form.watch('businessContext.competitiveAlternatives') || [];
                if (checked) {
                  form.setValue('businessContext.competitiveAlternatives', [...current, alternative]);
                } else {
                  form.setValue('businessContext.competitiveAlternatives', current.filter(item => item !== alternative));
                }
              }}
              disabled={readonly}
            />
            <Label htmlFor={`alternative-${alternative}`} className="text-sm">{alternative}</Label>
          </div>
        ))}
      </div>
    </div>
  </div>
);

const LegalAgreementsStep: React.FC<{ form: any; readonly: boolean }> = ({ form, readonly }) => (
  <div className="space-y-6">
    <Alert>
      <CheckCircle className="h-4 w-4" />
      <AlertDescription>
        Please review and accept the required legal agreements to proceed with your POC request.
      </AlertDescription>
    </Alert>

    <div className="space-y-6">
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="pt-6">
          <div className="flex items-start space-x-3">
            <Checkbox
              id="termsAccepted"
              checked={form.watch('legal.termsAccepted')}
              onCheckedChange={(checked) => form.setValue('legal.termsAccepted', checked)}
              disabled={readonly}
              className="mt-1"
            />
            <div className="flex-1">
              <Label htmlFor="termsAccepted" className="text-base font-medium">
                Terms of Service *
              </Label>
              <p className="text-sm text-gray-600 mt-2">
                I accept the <a href="/terms" target="_blank" className="text-blue-600 underline">Terms of Service</a> for
                the iSECTECH POC environment, including usage limitations, data handling policies, and service availability.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-green-200 bg-green-50">
        <CardContent className="pt-6">
          <div className="flex items-start space-x-3">
            <Checkbox
              id="privacyPolicyAccepted"
              checked={form.watch('legal.privacyPolicyAccepted')}
              onCheckedChange={(checked) => form.setValue('legal.privacyPolicyAccepted', checked)}
              disabled={readonly}
              className="mt-1"
            />
            <div className="flex-1">
              <Label htmlFor="privacyPolicyAccepted" className="text-base font-medium">
                Privacy Policy *
              </Label>
              <p className="text-sm text-gray-600 mt-2">
                I acknowledge and accept the <a href="/privacy" target="_blank" className="text-blue-600 underline">Privacy Policy</a>,
                including how my personal and company data will be collected, processed, and protected during the POC.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-purple-200 bg-purple-50">
        <CardContent className="pt-6">
          <div className="flex items-start space-x-3">
            <Checkbox
              id="dataProcessingConsent"
              checked={form.watch('legal.dataProcessingConsent')}
              onCheckedChange={(checked) => form.setValue('legal.dataProcessingConsent', checked)}
              disabled={readonly}
              className="mt-1"
            />
            <div className="flex-1">
              <Label htmlFor="dataProcessingConsent" className="text-base font-medium">
                Data Processing Consent *
              </Label>
              <p className="text-sm text-gray-600 mt-2">
                I consent to the processing of my data for the purposes of the POC evaluation, including analytics,
                support, and improvement of the service. Data will be processed according to applicable data protection laws.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="pt-6">
          <div className="flex items-start space-x-3">
            <Checkbox
              id="marketingConsent"
              checked={form.watch('legal.marketingConsent')}
              onCheckedChange={(checked) => form.setValue('legal.marketingConsent', checked)}
              disabled={readonly}
              className="mt-1"
            />
            <div className="flex-1">
              <Label htmlFor="marketingConsent" className="text-base font-medium">
                Marketing Communications (Optional)
              </Label>
              <p className="text-sm text-gray-600 mt-2">
                I would like to receive marketing communications, product updates, and relevant cybersecurity insights
                from iSECTECH. You can unsubscribe at any time.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* NDA Section */}
      <Card className="border-orange-200 bg-orange-50">
        <CardContent className="pt-6">
          <div className="space-y-4">
            <div className="flex items-start space-x-3">
              <Checkbox
                id="ndaRequired"
                checked={form.watch('legal.nda.required')}
                onCheckedChange={(checked) => form.setValue('legal.nda.required', checked)}
                disabled={readonly}
                className="mt-1"
              />
              <div className="flex-1">
                <Label htmlFor="ndaRequired" className="text-base font-medium">
                  Non-Disclosure Agreement Required
                </Label>
                <p className="text-sm text-gray-600 mt-2">
                  Our organization requires a mutual NDA before proceeding with the POC evaluation.
                </p>
              </div>
            </div>

            {form.watch('legal.nda.required') && (
              <div className="ml-6 space-y-4">
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Our legal team will contact you to execute a mutual NDA before your POC environment is provisioned.
                    This typically takes 3-5 business days.
                  </AlertDescription>
                </Alert>

                <div className="flex items-center space-x-3">
                  <Checkbox
                    id="ndaAccepted"
                    checked={form.watch('legal.nda.accepted')}
                    onCheckedChange={(checked) => form.setValue('legal.nda.accepted', checked)}
                    disabled={readonly}
                  />
                  <Label htmlFor="ndaAccepted">
                    I understand that an NDA will be required and agree to the additional setup time
                  </Label>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>

    {/* Summary */}
    <Card className="bg-gray-50">
      <CardContent className="pt-6">
        <h3 className="font-semibold mb-3">Summary</h3>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span>Estimated Setup Time:</span>
            <span className="font-medium">
              {form.watch('legal.nda.required') ? '5-7 business days' : '2-4 hours'}
            </span>
          </div>
          <div className="flex justify-between">
            <span>POC Duration:</span>
            <span className="font-medium">{form.watch('pocRequirements.durationDays')} days</span>
          </div>
          <div className="flex justify-between">
            <span>POC Tier:</span>
            <span className="font-medium capitalize">{form.watch('pocRequirements.pocTier')}</span>
          </div>
          <div className="flex justify-between">
            <span>Expected Users:</span>
            <span className="font-medium">{form.watch('pocRequirements.expectedUsers')}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  </div>
);

export default POCSignupPortal;