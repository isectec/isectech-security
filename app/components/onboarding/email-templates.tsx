/**
 * Email Templates for Onboarding Communications
 * Production-grade HTML email templates with white-labeling support
 */

import React from 'react';

// Base template wrapper with branding
export const EmailTemplateWrapper: React.FC<{
  children: React.ReactNode;
  brandingConfig?: {
    companyName?: string;
    logoUrl?: string;
    primaryColor?: string;
    secondaryColor?: string;
    customDomain?: string;
    supportEmail?: string;
  };
}> = ({ children, brandingConfig }) => {
  const {
    companyName = 'iSECTECH Protect',
    logoUrl = '/logo.png',
    primaryColor = '#007bff',
    secondaryColor = '#6c757d',
    customDomain = 'isectech.com',
    supportEmail = 'support@isectech.com',
  } = brandingConfig || {};

  return (
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta httpEquiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>{companyName} - Security Platform</title>
        <style type="text/css">
          {`
            /* Reset styles */
            body, table, td, p, a, li, blockquote { 
              -webkit-text-size-adjust: 100%; 
              -ms-text-size-adjust: 100%; 
            }
            table, td { 
              mso-table-lspace: 0pt; 
              mso-table-rspace: 0pt; 
            }
            img { 
              -ms-interpolation-mode: bicubic; 
            }

            /* Remove spacing around Outlook 07, 10 tables */
            table { 
              border-collapse: collapse !important; 
            }

            /* Base styles */
            body {
              width: 100% !important;
              height: 100%;
              background-color: #f6f9fc;
              margin: 0;
              padding: 0;
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
              line-height: 1.6;
              color: #333333;
            }

            .email-wrapper {
              width: 100%;
              background-color: #f6f9fc;
              padding: 20px 0;
            }

            .email-content {
              max-width: 600px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
              overflow: hidden;
            }

            .email-header {
              background-color: ${primaryColor};
              padding: 30px;
              text-align: center;
            }

            .email-header img {
              max-height: 50px;
              width: auto;
            }

            .email-header h1 {
              color: #ffffff;
              margin: 15px 0 0 0;
              font-size: 24px;
              font-weight: 600;
            }

            .email-body {
              padding: 40px 30px;
            }

            .email-footer {
              background-color: #f8f9fa;
              padding: 30px;
              text-align: center;
              border-top: 1px solid #e9ecef;
            }

            .button {
              display: inline-block;
              padding: 12px 24px;
              background-color: ${primaryColor};
              color: #ffffff;
              text-decoration: none;
              border-radius: 6px;
              font-weight: 600;
              margin: 20px 0;
            }

            .button:hover {
              background-color: ${secondaryColor};
            }

            .checklist-item {
              background-color: #f8f9fa;
              border: 1px solid #e9ecef;
              border-radius: 6px;
              padding: 15px;
              margin: 10px 0;
            }

            .checklist-item h4 {
              margin: 0 0 8px 0;
              color: ${primaryColor};
            }

            .progress-bar {
              width: 100%;
              height: 8px;
              background-color: #e9ecef;
              border-radius: 4px;
              overflow: hidden;
              margin: 15px 0;
            }

            .progress-fill {
              height: 100%;
              background-color: ${primaryColor};
              border-radius: 4px;
            }

            .stats-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
              gap: 20px;
              margin: 20px 0;
            }

            .stat-item {
              text-align: center;
              padding: 20px;
              background-color: #f8f9fa;
              border-radius: 6px;
            }

            .stat-number {
              font-size: 32px;
              font-weight: bold;
              color: ${primaryColor};
              margin: 0;
            }

            .stat-label {
              font-size: 14px;
              color: ${secondaryColor};
              margin: 5px 0 0 0;
            }

            /* Mobile responsive */
            @media screen and (max-width: 600px) {
              .email-content {
                margin: 10px;
                border-radius: 0;
              }
              
              .email-body, .email-header, .email-footer {
                padding: 20px !important;
              }

              .stats-grid {
                grid-template-columns: repeat(2, 1fr);
              }

              .stat-number {
                font-size: 24px;
              }
            }

            /* Dark mode support */
            @media (prefers-color-scheme: dark) {
              .email-content {
                background-color: #1a1a1a;
              }
              
              .email-body {
                color: #ffffff;
              }

              .checklist-item {
                background-color: #2d2d2d;
                border-color: #404040;
              }

              .stat-item {
                background-color: #2d2d2d;
              }
            }
          `}
        </style>
      </head>
      <body>
        <div className="email-wrapper">
          <div className="email-content">
            <div className="email-header">
              <img src={logoUrl} alt={companyName} />
              <h1>{companyName}</h1>
            </div>
            <div className="email-body">
              {children}
            </div>
            <div className="email-footer">
              <p style={{ margin: '0 0 10px 0', fontSize: '14px', color: '#6c757d' }}>
                Questions? Contact us at{' '}
                <a href={`mailto:${supportEmail}`} style={{ color: primaryColor }}>
                  {supportEmail}
                </a>
              </p>
              <p style={{ margin: '0', fontSize: '12px', color: '#adb5bd' }}>
                © {new Date().getFullYear()} {companyName}. All rights reserved.
              </p>
              <p style={{ margin: '10px 0 0 0', fontSize: '12px' }}>
                <a 
                  href="{{unsubscribe_url}}" 
                  style={{ color: '#adb5bd', textDecoration: 'underline' }}
                >
                  Unsubscribe
                </a>
              </p>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
};

// Welcome Email Template
export const WelcomeEmailTemplate: React.FC<{
  recipientName: string;
  companyName: string;
  platformName: string;
  loginUrl: string;
  supportEmail: string;
  gettingStartedUrl?: string;
  brandingConfig?: any;
}> = ({ 
  recipientName, 
  companyName, 
  platformName, 
  loginUrl, 
  supportEmail, 
  gettingStartedUrl,
  brandingConfig 
}) => (
  <EmailTemplateWrapper brandingConfig={brandingConfig}>
    <h2 style={{ marginTop: 0, color: brandingConfig?.primaryColor || '#007bff' }}>
      Welcome to {platformName}!
    </h2>
    
    <p>Dear {recipientName},</p>
    
    <p>
      Welcome to {platformName}! We're excited to have {companyName} join our security platform. 
      Your account has been successfully created and you're ready to begin securing your organization.
    </p>

    <div style={{ backgroundColor: '#f8f9fa', padding: '20px', borderRadius: '6px', margin: '20px 0' }}>
      <h3 style={{ marginTop: 0, color: '#333' }}>What's Next?</h3>
      <ul style={{ paddingLeft: '20px', margin: 0 }}>
        <li>Complete your onboarding checklist</li>
        <li>Configure your security policies</li>
        <li>Set up your team members and roles</li>
        <li>Connect your first data sources</li>
      </ul>
    </div>

    <div style={{ textAlign: 'center', margin: '30px 0' }}>
      <a href={loginUrl} className="button">
        Access Your Security Platform
      </a>
    </div>

    {gettingStartedUrl && (
      <p style={{ textAlign: 'center' }}>
        Need help getting started? Check out our{' '}
        <a href={gettingStartedUrl} style={{ color: brandingConfig?.primaryColor || '#007bff' }}>
          Getting Started Guide
        </a>
      </p>
    )}

    <p>
      Our team is here to support you every step of the way. If you have any questions 
      or need assistance, don't hesitate to reach out to us at{' '}
      <a href={`mailto:${supportEmail}`} style={{ color: brandingConfig?.primaryColor || '#007bff' }}>
        {supportEmail}
      </a>.
    </p>

    <p>Welcome aboard!</p>
    <p style={{ marginBottom: 0 }}>
      <strong>The {platformName} Team</strong>
    </p>
  </EmailTemplateWrapper>
);

// Onboarding Step Notification Template
export const OnboardingStepTemplate: React.FC<{
  recipientName: string;
  stepName: string;
  stepDescription: string;
  actionUrl?: string;
  estimatedTime?: number;
  dueDate?: string;
  brandingConfig?: any;
}> = ({ 
  recipientName, 
  stepName, 
  stepDescription, 
  actionUrl, 
  estimatedTime, 
  dueDate,
  brandingConfig 
}) => (
  <EmailTemplateWrapper brandingConfig={brandingConfig}>
    <h2 style={{ marginTop: 0, color: brandingConfig?.primaryColor || '#007bff' }}>
      Next Step: {stepName}
    </h2>
    
    <p>Hello {recipientName},</p>
    
    <p>You're making great progress with your onboarding! Your next step is ready:</p>

    <div className="checklist-item" style={{ margin: '20px 0' }}>
      <h4>{stepName}</h4>
      <p style={{ margin: '8px 0' }}>{stepDescription}</p>
      
      {estimatedTime && (
        <p style={{ margin: '8px 0', fontSize: '14px', color: '#6c757d' }}>
          <strong>Estimated time:</strong> {estimatedTime} minutes
        </p>
      )}
      
      {dueDate && (
        <p style={{ margin: '8px 0', fontSize: '14px', color: '#dc3545' }}>
          <strong>Due date:</strong> {dueDate}
        </p>
      )}
    </div>

    {actionUrl && (
      <div style={{ textAlign: 'center', margin: '30px 0' }}>
        <a href={actionUrl} className="button">
          Complete This Step
        </a>
      </div>
    )}

    <p>
      Completing your onboarding steps ensures you get the most out of your security platform. 
      Each step is designed to enhance your security posture and streamline your operations.
    </p>

    <p>Need assistance? Our support team is available 24/7 to help you succeed.</p>
  </EmailTemplateWrapper>
);

// Checklist Item Reminder Template
export const ChecklistReminderTemplate: React.FC<{
  recipientName: string;
  itemTitle: string;
  itemDescription: string;
  checklistTitle: string;
  actionUrl?: string;
  daysOverdue?: number;
  totalItems: number;
  completedItems: number;
  brandingConfig?: any;
}> = ({ 
  recipientName, 
  itemTitle, 
  itemDescription, 
  checklistTitle, 
  actionUrl, 
  daysOverdue,
  totalItems,
  completedItems,
  brandingConfig 
}) => {
  const progressPercent = totalItems > 0 ? (completedItems / totalItems) * 100 : 0;
  
  return (
    <EmailTemplateWrapper brandingConfig={brandingConfig}>
      <h2 style={{ marginTop: 0, color: brandingConfig?.primaryColor || '#007bff' }}>
        {daysOverdue ? 'Overdue Reminder' : 'Friendly Reminder'}: {itemTitle}
      </h2>
      
      <p>Hello {recipientName},</p>
      
      <p>
        {daysOverdue 
          ? `This is a reminder about an overdue item in your ${checklistTitle}.`
          : `This is a friendly reminder about a pending item in your ${checklistTitle}.`
        }
      </p>

      <div className="checklist-item" style={{ margin: '20px 0' }}>
        <h4>{itemTitle}</h4>
        <p style={{ margin: '8px 0' }}>{itemDescription}</p>
        
        {daysOverdue && (
          <p style={{ margin: '8px 0', fontSize: '14px', color: '#dc3545', fontWeight: 'bold' }}>
            Overdue by {daysOverdue} day{daysOverdue > 1 ? 's' : ''}
          </p>
        )}
      </div>

      {/* Progress indicator */}
      <div style={{ margin: '30px 0' }}>
        <h4 style={{ margin: '0 0 10px 0' }}>Your Progress</h4>
        <div className="progress-bar">
          <div 
            className="progress-fill" 
            style={{ width: `${progressPercent}%` }}
          ></div>
        </div>
        <p style={{ margin: '10px 0 0 0', fontSize: '14px', color: '#6c757d' }}>
          {completedItems} of {totalItems} items completed ({Math.round(progressPercent)}%)
        </p>
      </div>

      {actionUrl && (
        <div style={{ textAlign: 'center', margin: '30px 0' }}>
          <a href={actionUrl} className="button">
            Complete This Item
          </a>
        </div>
      )}

      <p>
        Completing your onboarding checklist ensures your security platform is properly configured 
        and your organization is fully protected. Each item plays an important role in your overall security posture.
      </p>
    </EmailTemplateWrapper>
  );
};

// Checklist Completion Template
export const ChecklistCompletionTemplate: React.FC<{
  recipientName: string;
  checklistTitle: string;
  completionDate: string;
  totalItems: number;
  timeToComplete?: string;
  nextSteps: string[];
  dashboardUrl?: string;
  brandingConfig?: any;
}> = ({ 
  recipientName, 
  checklistTitle, 
  completionDate, 
  totalItems, 
  timeToComplete,
  nextSteps,
  dashboardUrl,
  brandingConfig 
}) => (
  <EmailTemplateWrapper brandingConfig={brandingConfig}>
    <div style={{ textAlign: 'center', margin: '0 0 30px 0' }}>
      <div style={{ 
        fontSize: '48px', 
        margin: '0 0 15px 0',
        color: '#28a745'
      }}>
        🎉
      </div>
      <h2 style={{ marginTop: 0, color: '#28a745' }}>
        Congratulations! Onboarding Complete
      </h2>
    </div>
    
    <p>Dear {recipientName},</p>
    
    <p>
      Fantastic work! You've successfully completed your <strong>{checklistTitle}</strong>. 
      Your security platform is now fully configured and ready to protect your organization.
    </p>

    <div className="stats-grid" style={{ margin: '30px 0' }}>
      <div className="stat-item">
        <div className="stat-number">{totalItems}</div>
        <div className="stat-label">Items Completed</div>
      </div>
      <div className="stat-item">
        <div className="stat-number">100%</div>
        <div className="stat-label">Complete</div>
      </div>
      {timeToComplete && (
        <div className="stat-item">
          <div className="stat-number" style={{ fontSize: '20px' }}>{timeToComplete}</div>
          <div className="stat-label">Total Time</div>
        </div>
      )}
    </div>

    <div style={{ backgroundColor: '#d4edda', padding: '20px', borderRadius: '6px', margin: '20px 0', border: '1px solid #c3e6cb' }}>
      <h3 style={{ marginTop: 0, color: '#155724' }}>What's Next?</h3>
      <ul style={{ paddingLeft: '20px', margin: '0', color: '#155724' }}>
        {nextSteps.map((step, index) => (
          <li key={index} style={{ marginBottom: '8px' }}>{step}</li>
        ))}
      </ul>
    </div>

    {dashboardUrl && (
      <div style={{ textAlign: 'center', margin: '30px 0' }}>
        <a href={dashboardUrl} className="button">
          Access Your Security Dashboard
        </a>
      </div>
    )}

    <p>
      Your organization is now protected by enterprise-grade security monitoring and threat detection. 
      Our platform will continuously monitor your environment and alert you to any potential security issues.
    </p>

    <p>
      Thank you for choosing us to secure your organization. We're here to support you every step of the way 
      as you leverage your new security capabilities.
    </p>

    <p>Welcome to the next level of security!</p>
    <p style={{ marginBottom: 0 }}>
      <strong>Your Security Team</strong>
    </p>
  </EmailTemplateWrapper>
);

// Onboarding Reminder Template
export const OnboardingReminderTemplate: React.FC<{
  recipientName: string;
  companyName: string;
  platformName: string;
  pendingSteps: Array<{ name: string; description: string; daysOverdue?: number }>;
  progressPercent: number;
  totalSteps: number;
  completedSteps: number;
  continueUrl: string;
  brandingConfig?: any;
}> = ({ 
  recipientName, 
  companyName, 
  platformName, 
  pendingSteps, 
  progressPercent,
  totalSteps,
  completedSteps,
  continueUrl,
  brandingConfig 
}) => (
  <EmailTemplateWrapper brandingConfig={brandingConfig}>
    <h2 style={{ marginTop: 0, color: brandingConfig?.primaryColor || '#007bff' }}>
      Continue Your {platformName} Setup
    </h2>
    
    <p>Hello {recipientName},</p>
    
    <p>
      We noticed you haven't finished setting up your {platformName} account for {companyName}. 
      You're {Math.round(progressPercent)}% of the way there!
    </p>

    {/* Progress indicator */}
    <div style={{ margin: '30px 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <span style={{ fontWeight: 'bold' }}>Your Progress</span>
        <span style={{ color: '#6c757d' }}>{completedSteps} of {totalSteps} steps</span>
      </div>
      <div className="progress-bar">
        <div 
          className="progress-fill" 
          style={{ width: `${progressPercent}%` }}
        ></div>
      </div>
    </div>

    <h3>Remaining Steps:</h3>
    {pendingSteps.map((step, index) => (
      <div key={index} className="checklist-item" style={{ margin: '10px 0' }}>
        <h4 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          {step.name}
          {step.daysOverdue && step.daysOverdue > 0 && (
            <span style={{ 
              fontSize: '12px', 
              color: '#dc3545', 
              fontWeight: 'normal',
              backgroundColor: '#f8d7da',
              padding: '2px 8px',
              borderRadius: '12px'
            }}>
              {step.daysOverdue} day{step.daysOverdue > 1 ? 's' : ''} overdue
            </span>
          )}
        </h4>
        <p style={{ margin: '8px 0 0 0' }}>{step.description}</p>
      </div>
    ))}

    <div style={{ textAlign: 'center', margin: '30px 0' }}>
      <a href={continueUrl} className="button">
        Continue Setup
      </a>
    </div>

    <div style={{ backgroundColor: '#fff3cd', padding: '15px', borderRadius: '6px', margin: '20px 0', border: '1px solid #ffeaa7' }}>
      <p style={{ margin: 0, color: '#856404' }}>
        <strong>💡 Pro Tip:</strong> Completing your setup now will ensure your security monitoring 
        is active and protecting your organization as soon as possible.
      </p>
    </div>

    <p>
      Need help? Our support team is standing by to assist you with any questions or challenges 
      you might encounter during setup.
    </p>
  </EmailTemplateWrapper>
);

// Export all templates
export const EmailTemplates = {
  Welcome: WelcomeEmailTemplate,
  OnboardingStep: OnboardingStepTemplate,
  ChecklistReminder: ChecklistReminderTemplate,
  ChecklistCompletion: ChecklistCompletionTemplate,
  OnboardingReminder: OnboardingReminderTemplate,
};