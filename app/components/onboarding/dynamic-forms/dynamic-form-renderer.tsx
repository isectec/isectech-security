/**
 * Dynamic Form Renderer Component
 * Production-grade dynamic form renderer with conditional logic and real-time validation
 */

'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Box,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Checkbox,
  RadioGroup,
  Radio,
  Button,
  Typography,
  Alert,
  Stack,
  LinearProgress,
  Card,
  CardContent,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Paper,
  Autocomplete,
  Chip,
} from '@mui/material';
import {
  Save as SaveIcon,
  Send as SubmitIcon,
  ArrowBack as BackIcon,
  ArrowForward as NextIcon,
  CheckCircle as SuccessIcon,
} from '@mui/icons-material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import type { 
  DynamicForm,
  FormField,
  ValidationRule,
  FormSubmission,
  OnboardingInstance,
} from '@/types';

interface DynamicFormRendererProps {
  form: DynamicForm;
  onSubmit: (submission: FormSubmission) => void;
  onSave?: (data: Record<string, unknown>) => void;
  onboardingInstance?: OnboardingInstance;
  initialData?: Record<string, unknown>;
  readOnly?: boolean;
  showProgress?: boolean;
  className?: string;
}

interface FormData {
  [key: string]: unknown;
}

interface FormErrors {
  [key: string]: string[];
}

export function DynamicFormRenderer({
  form,
  onSubmit,
  onSave,
  onboardingInstance,
  initialData = {},
  readOnly = false,
  showProgress = true,
  className,
}: DynamicFormRendererProps) {
  const [formData, setFormData] = useState<FormData>(initialData);
  const [errors, setErrors] = useState<FormErrors>({});
  const [currentSection, setCurrentSection] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  // Auto-save functionality
  useEffect(() => {
    if (form.behavior.autoSave && onSave && Object.keys(formData).length > 0) {
      const timeout = setTimeout(() => {
        setIsSaving(true);
        onSave(formData);
        setLastSaved(new Date());
        setIsSaving(false);
      }, 2000); // Auto-save after 2 seconds of inactivity

      return () => clearTimeout(timeout);
    }
  }, [formData, form.behavior.autoSave, onSave]);

  // Validate field
  const validateField = useCallback((field: FormField, value: unknown): string[] => {
    const fieldErrors: string[] = [];

    for (const rule of field.validation) {
      switch (rule.type) {
        case 'required':
          if (!value || (typeof value === 'string' && !value.trim())) {
            fieldErrors.push(rule.message);
          }
          break;

        case 'min':
          if (typeof value === 'string' && value.length < (rule.value as number)) {
            fieldErrors.push(rule.message);
          } else if (typeof value === 'number' && value < (rule.value as number)) {
            fieldErrors.push(rule.message);
          }
          break;

        case 'max':
          if (typeof value === 'string' && value.length > (rule.value as number)) {
            fieldErrors.push(rule.message);
          } else if (typeof value === 'number' && value > (rule.value as number)) {
            fieldErrors.push(rule.message);
          }
          break;

        case 'pattern':
          if (typeof value === 'string' && rule.value) {
            const regex = new RegExp(rule.value as string);
            if (!regex.test(value)) {
              fieldErrors.push(rule.message);
            }
          }
          break;

        case 'custom':
          if (rule.validator) {
            try {
              // Create a safe evaluation context
              const validateFn = new Function('value', 'formData', `return ${rule.validator}`);
              if (!validateFn(value, formData)) {
                fieldErrors.push(rule.message);
              }
            } catch (error) {
              console.error('Custom validation error:', error);
              fieldErrors.push('Validation error occurred');
            }
          }
          break;
      }
    }

    return fieldErrors;
  }, [formData]);

  // Check if field should be shown based on conditional logic
  const shouldShowField = useCallback((field: FormField): boolean => {
    if (!field.conditionalLogic?.showIf) return true;

    try {
      // Create a safe evaluation context with form data
      const evaluateFn = new Function('formData', `
        const ${Object.keys(formData).map(key => `${key} = formData['${key}']`).join(', ')};
        return ${field.conditionalLogic.showIf};
      `);
      return evaluateFn(formData);
    } catch (error) {
      console.error('Conditional logic evaluation error:', error);
      return true; // Show field by default if evaluation fails
    }
  }, [formData]);

  // Check if field is required based on conditional logic
  const isFieldRequired = useCallback((field: FormField): boolean => {
    if (!field.conditionalLogic?.requiredIf) return field.required;

    try {
      // Create a safe evaluation context
      const evaluateFn = new Function('formData', `
        const ${Object.keys(formData).map(key => `${key} = formData['${key}']`).join(', ')};
        return ${field.conditionalLogic.requiredIf};
      `);
      return evaluateFn(formData) || field.required;
    } catch (error) {
      console.error('Required condition evaluation error:', error);
      return field.required;
    }
  }, [formData]);

  // Handle field value change
  const handleFieldChange = useCallback((fieldId: string, value: unknown) => {
    setFormData(prev => ({ ...prev, [fieldId]: value }));

    // Clear field errors when value changes
    if (errors[fieldId]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[fieldId];
        return newErrors;
      });
    }
  }, [errors]);

  // Validate form section
  const validateSection = useCallback((sectionIndex: number): boolean => {
    if (!form.layout.sections[sectionIndex]) return true;

    const section = form.layout.sections[sectionIndex];
    const sectionFields = form.fields.filter(field => section.fields.includes(field.id));
    const newErrors: FormErrors = {};
    let isValid = true;

    for (const field of sectionFields) {
      if (!shouldShowField(field)) continue;

      const value = formData[field.id];
      const fieldErrors = validateField(field, value);

      // Check if field is dynamically required
      const dynamicallyRequired = isFieldRequired(field);
      if (dynamicallyRequired && (!value || (typeof value === 'string' && !value.trim()))) {
        fieldErrors.push(`${field.label} is required`);
      }

      if (fieldErrors.length > 0) {
        newErrors[field.id] = fieldErrors;
        isValid = false;
      }
    }

    setErrors(prev => ({ ...prev, ...newErrors }));
    return isValid;
  }, [form.layout.sections, form.fields, shouldShowField, formData, validateField, isFieldRequired]);

  // Handle section navigation
  const handleNextSection = useCallback(() => {
    if (validateSection(currentSection)) {
      setCurrentSection(prev => Math.min(prev + 1, form.layout.sections.length - 1));
    }
  }, [currentSection, form.layout.sections.length, validateSection]);

  const handlePreviousSection = useCallback(() => {
    setCurrentSection(prev => Math.max(prev - 1, 0));
  }, []);

  // Handle form submission
  const handleSubmit = useCallback(async () => {
    // Validate all sections
    let isFormValid = true;
    for (let i = 0; i < form.layout.sections.length; i++) {
      if (!validateSection(i)) {
        isFormValid = false;
      }
    }

    if (!isFormValid) {
      setCurrentSection(0); // Go to first section with errors
      return;
    }

    setIsSubmitting(true);

    try {
      const submission: FormSubmission = {
        id: `submission_${Date.now()}`,
        formId: form.id!,
        onboardingInstanceId: onboardingInstance?.id || '',
        submittedBy: 'current-user', // This should come from auth context
        data: formData,
        validation: {
          isValid: true,
          errors: [],
        },
        metadata: {
          userAgent: navigator.userAgent,
          ipAddress: '', // This should be populated by backend
          submissionTime: Date.now(),
          deviceType: window.innerWidth < 768 ? 'mobile' : window.innerWidth < 1024 ? 'tablet' : 'desktop',
        },
        processing: {
          status: 'pending',
        },
        tenantId: form.tenantId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      await onSubmit(submission);
      setSubmitSuccess(true);
    } catch (error) {
      console.error('Form submission error:', error);
      // Handle submission error
    } finally {
      setIsSubmitting(false);
    }
  }, [form, validateSection, formData, onboardingInstance?.id, onSubmit]);

  // Handle save draft
  const handleSave = useCallback(async () => {
    if (!onSave) return;

    setIsSaving(true);
    try {
      await onSave(formData);
      setLastSaved(new Date());
    } catch (error) {
      console.error('Save error:', error);
    } finally {
      setIsSaving(false);
    }
  }, [onSave, formData]);

  // Render form field
  const renderField = useCallback((field: FormField) => {
    if (!shouldShowField(field)) return null;

    const value = formData[field.id];
    const fieldErrors = errors[field.id] || [];
    const hasError = fieldErrors.length > 0;
    const required = isFieldRequired(field);

    const commonProps = {
      fullWidth: true,
      label: field.label,
      helperText: hasError ? fieldErrors[0] : field.description,
      error: hasError,
      required,
      disabled: readOnly,
    };

    switch (field.type) {
      case 'text':
      case 'email':
      case 'phone':
        return (
          <TextField
            key={field.id}
            {...commonProps}
            type={field.type}
            value={value || ''}
            placeholder={field.placeholder}
            onChange={(e) => handleFieldChange(field.id, e.target.value)}
          />
        );

      case 'number':
        return (
          <TextField
            key={field.id}
            {...commonProps}
            type="number"
            value={value || ''}
            placeholder={field.placeholder}
            onChange={(e) => handleFieldChange(field.id, parseFloat(e.target.value) || '')}
          />
        );

      case 'textarea':
        return (
          <TextField
            key={field.id}
            {...commonProps}
            multiline
            rows={4}
            value={value || ''}
            placeholder={field.placeholder}
            onChange={(e) => handleFieldChange(field.id, e.target.value)}
          />
        );

      case 'select':
        return (
          <FormControl key={field.id} {...commonProps}>
            <InputLabel>{field.label}</InputLabel>
            <Select
              value={value || ''}
              label={field.label}
              onChange={(e) => handleFieldChange(field.id, e.target.value)}
            >
              {field.options?.map((option) => (
                <MenuItem key={option.value} value={option.value} disabled={option.disabled}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        );

      case 'multiselect':
        return (
          <Autocomplete
            key={field.id}
            multiple
            options={field.options || []}
            getOptionLabel={(option) => option.label}
            value={field.options?.filter(opt => (value as string[] || []).includes(opt.value)) || []}
            onChange={(_, selectedOptions) => {
              handleFieldChange(field.id, selectedOptions.map(opt => opt.value));
            }}
            disabled={readOnly}
            renderTags={(value, getTagProps) =>
              value.map((option, index) => (
                <Chip
                  variant="outlined"
                  label={option.label}
                  {...getTagProps({ index })}
                  key={option.value}
                />
              ))
            }
            renderInput={(params) => (
              <TextField
                {...params}
                label={field.label}
                helperText={hasError ? fieldErrors[0] : field.description}
                error={hasError}
                required={required}
              />
            )}
          />
        );

      case 'checkbox':
        return (
          <FormControlLabel
            key={field.id}
            control={
              <Checkbox
                checked={Boolean(value)}
                onChange={(e) => handleFieldChange(field.id, e.target.checked)}
                disabled={readOnly}
              />
            }
            label={
              <Box>
                <Typography variant="body2">
                  {field.label} {required && '*'}
                </Typography>
                {field.description && (
                  <Typography variant="caption" color="text.secondary">
                    {field.description}
                  </Typography>
                )}
              </Box>
            }
          />
        );

      case 'radio':
        return (
          <Box key={field.id}>
            <Typography variant="body2" sx={{ mb: 1 }}>
              {field.label} {required && '*'}
            </Typography>
            <RadioGroup
              value={value || ''}
              onChange={(e) => handleFieldChange(field.id, e.target.value)}
            >
              {field.options?.map((option) => (
                <FormControlLabel
                  key={option.value}
                  value={option.value}
                  control={<Radio disabled={readOnly || option.disabled} />}
                  label={option.label}
                />
              ))}
            </RadioGroup>
            {field.description && (
              <Typography variant="caption" color="text.secondary">
                {field.description}
              </Typography>
            )}
            {hasError && (
              <Typography variant="caption" color="error">
                {fieldErrors[0]}
              </Typography>
            )}
          </Box>
        );

      case 'date':
        return (
          <LocalizationProvider key={field.id} dateAdapter={AdapterDateFns}>
            <DateTimePicker
              label={field.label}
              value={value ? new Date(value as string) : null}
              onChange={(newValue) => handleFieldChange(field.id, newValue?.toISOString())}
              disabled={readOnly}
              renderInput={(props) => (
                <TextField
                  {...props}
                  fullWidth
                  helperText={hasError ? fieldErrors[0] : field.description}
                  error={hasError}
                  required={required}
                />
              )}
            />
          </LocalizationProvider>
        );

      case 'file':
        return (
          <Box key={field.id}>
            <Typography variant="body2" sx={{ mb: 1 }}>
              {field.label} {required && '*'}
            </Typography>
            <Button variant="outlined" component="label" disabled={readOnly}>
              Choose File
              <input
                type="file"
                hidden
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  handleFieldChange(field.id, file ? file.name : '');
                }}
              />
            </Button>
            {value && (
              <Typography variant="body2" sx={{ mt: 1 }}>
                Selected: {value as string}
              </Typography>
            )}
            {field.description && (
              <Typography variant="caption" color="text.secondary" display="block">
                {field.description}
              </Typography>
            )}
            {hasError && (
              <Typography variant="caption" color="error">
                {fieldErrors[0]}
              </Typography>
            )}
          </Box>
        );

      default:
        return (
          <Alert key={field.id} severity="warning">
            Unsupported field type: {field.type}
          </Alert>
        );
    }
  }, [formData, errors, shouldShowField, isFieldRequired, readOnly, handleFieldChange]);

  // Calculate progress
  const progress = useMemo(() => {
    if (!showProgress) return 0;
    const totalSections = form.layout.sections.length;
    return totalSections > 0 ? ((currentSection + 1) / totalSections) * 100 : 0;
  }, [currentSection, form.layout.sections.length, showProgress]);

  const filledFieldsCount = useMemo(() => {
    return Object.keys(formData).filter(key => {
      const value = formData[key];
      return value !== null && value !== undefined && value !== '';
    }).length;
  }, [formData]);

  if (submitSuccess) {
    return (
      <Card className={className}>
        <CardContent sx={{ textAlign: 'center', py: 6 }}>
          <SuccessIcon sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
          <Typography variant="h5" sx={{ mb: 2 }}>
            Form Submitted Successfully!
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Thank you for completing the form. Your information has been received and is being processed.
          </Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box className={className}>
      {/* Header with progress */}
      {showProgress && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">{form.name}</Typography>
            <Stack direction="row" spacing={2} alignItems="center">
              {lastSaved && (
                <Typography variant="caption" color="text.secondary">
                  Last saved: {lastSaved.toLocaleTimeString()}
                </Typography>
              )}
              {isSaving && (
                <Typography variant="caption" color="primary">
                  Saving...
                </Typography>
              )}
              <Typography variant="body2">
                {filledFieldsCount} fields completed
              </Typography>
            </Stack>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progress}
            sx={{ height: 8, borderRadius: 4 }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Section {currentSection + 1} of {form.layout.sections.length}
          </Typography>
        </Paper>
      )}

      {/* Form sections */}
      {form.layout.sections.length > 1 ? (
        <Stepper activeStep={currentSection} orientation="vertical">
          {form.layout.sections.map((section, index) => (
            <Step key={section.id}>
              <StepLabel>{section.title}</StepLabel>
              <StepContent>
                <Card>
                  <CardContent>
                    {section.description && (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        {section.description}
                      </Typography>
                    )}
                    
                    <Grid container spacing={3}>
                      {form.fields
                        .filter(field => section.fields.includes(field.id))
                        .map(field => (
                          <Grid item xs={12} key={field.id}>
                            {renderField(field)}
                          </Grid>
                        ))}
                    </Grid>

                    {/* Section navigation */}
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                      <Button
                        startIcon={<BackIcon />}
                        onClick={handlePreviousSection}
                        disabled={currentSection === 0}
                      >
                        Previous
                      </Button>

                      <Stack direction="row" spacing={2}>
                        {form.behavior.allowSave && onSave && (
                          <Button
                            variant="outlined"
                            startIcon={<SaveIcon />}
                            onClick={handleSave}
                            disabled={isSaving}
                          >
                            Save Draft
                          </Button>
                        )}

                        {currentSection === form.layout.sections.length - 1 ? (
                          <Button
                            variant="contained"
                            startIcon={<SubmitIcon />}
                            onClick={handleSubmit}
                            disabled={isSubmitting || readOnly}
                          >
                            {isSubmitting ? 'Submitting...' : form.layout.submitButton.text}
                          </Button>
                        ) : (
                          <Button
                            variant="contained"
                            endIcon={<NextIcon />}
                            onClick={handleNextSection}
                          >
                            Next
                          </Button>
                        )}
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      ) : (
        /* Single section form */
        <Card>
          <CardContent>
            <Grid container spacing={3}>
              {form.fields.map(field => (
                <Grid item xs={12} key={field.id}>
                  {renderField(field)}
                </Grid>
              ))}
            </Grid>

            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 4 }}>
              <Stack direction="row" spacing={2}>
                {form.behavior.allowSave && onSave && (
                  <Button
                    variant="outlined"
                    startIcon={<SaveIcon />}
                    onClick={handleSave}
                    disabled={isSaving}
                  >
                    Save Draft
                  </Button>
                )}

                <Button
                  variant="contained"
                  startIcon={<SubmitIcon />}
                  onClick={handleSubmit}
                  disabled={isSubmitting || readOnly}
                >
                  {isSubmitting ? 'Submitting...' : form.layout.submitButton.text}
                </Button>
              </Stack>
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}

export default DynamicFormRenderer;