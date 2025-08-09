/**
 * Dynamic Form Builder Component
 * Production-grade dynamic form builder with conditional logic and validation
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
  Card,
  CardContent,
  Typography,
  Button,
  IconButton,
  Alert,
  Stack,
  Chip,
  Autocomplete,
  Rating,
  Slider,
  Switch,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Paper,
  useTheme,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  DragIndicator as DragIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as PreviewIcon,
  Save as SaveIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import type { 
  DynamicForm,
  FormField,
  ValidationRule,
  FormSubmission,
  CustomerProfile,
} from '@/types';

interface DynamicFormBuilderProps {
  form?: DynamicForm;
  onSave: (form: DynamicForm) => void;
  onPreview?: (form: DynamicForm) => void;
  customerProfile?: CustomerProfile;
  className?: string;
}

interface FormFieldConfig extends FormField {
  tempId: string;
}

const fieldTypes = [
  { value: 'text', label: 'Text Input', description: 'Single line text field' },
  { value: 'email', label: 'Email', description: 'Email address input with validation' },
  { value: 'phone', label: 'Phone', description: 'Phone number input' },
  { value: 'number', label: 'Number', description: 'Numeric input field' },
  { value: 'date', label: 'Date', description: 'Date picker input' },
  { value: 'select', label: 'Select Dropdown', description: 'Single selection dropdown' },
  { value: 'multiselect', label: 'Multi-Select', description: 'Multiple selection dropdown' },
  { value: 'checkbox', label: 'Checkbox', description: 'True/false checkbox' },
  { value: 'radio', label: 'Radio Group', description: 'Single selection from options' },
  { value: 'textarea', label: 'Text Area', description: 'Multi-line text input' },
  { value: 'file', label: 'File Upload', description: 'File upload field' },
  { value: 'json', label: 'JSON Data', description: 'Structured JSON input' },
];

const validationTypes = [
  { value: 'required', label: 'Required', hasValue: false },
  { value: 'min', label: 'Minimum Length/Value', hasValue: true },
  { value: 'max', label: 'Maximum Length/Value', hasValue: true },
  { value: 'pattern', label: 'Regex Pattern', hasValue: true },
  { value: 'custom', label: 'Custom Validation', hasValue: true },
];

export function DynamicFormBuilder({
  form,
  onSave,
  onPreview,
  customerProfile,
  className,
}: DynamicFormBuilderProps) {
  const theme = useTheme();

  const [formConfig, setFormConfig] = useState<Partial<DynamicForm>>({
    name: form?.name || '',
    description: form?.description || '',
    version: form?.version || '1.0.0',
    customerType: form?.customerType || [],
    serviceTier: form?.serviceTier || [],
    fields: form?.fields || [],
    layout: form?.layout || {
      sections: [],
      submitButton: {
        text: 'Submit',
        position: 'center',
      },
    },
    styling: form?.styling || {
      theme: 'default',
      primaryColor: theme.palette.primary.main,
      customCss: '',
    },
    behavior: form?.behavior || {
      allowSave: true,
      autoSave: false,
      showProgress: true,
      allowBack: true,
    },
  });

  const [fields, setFields] = useState<FormFieldConfig[]>(
    form?.fields?.map((field, index) => ({
      ...field,
      tempId: `field_${index}`,
    })) || []
  );

  const [previewMode, setPreviewMode] = useState(false);
  const [selectedFieldIndex, setSelectedFieldIndex] = useState<number | null>(null);

  // Auto-generate field IDs
  const generateFieldId = useCallback((name: string) => {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '_');
  }, []);

  // Add new field
  const handleAddField = useCallback((type: string) => {
    const newField: FormFieldConfig = {
      id: `field_${Date.now()}`,
      tempId: `temp_${Date.now()}`,
      name: `field_${fields.length + 1}`,
      type: type as any,
      label: `New ${type.charAt(0).toUpperCase() + type.slice(1)} Field`,
      placeholder: '',
      description: '',
      required: false,
      validation: [],
      options: type === 'select' || type === 'multiselect' || type === 'radio' ? [
        { value: 'option1', label: 'Option 1' },
        { value: 'option2', label: 'Option 2' },
      ] : undefined,
      defaultValue: undefined,
      metadata: {
        category: 'general',
        sensitivity: 'internal',
        retention: 365,
      },
    };

    setFields(prev => [...prev, newField]);
    setSelectedFieldIndex(fields.length);
  }, [fields.length]);

  // Update field
  const handleUpdateField = useCallback((index: number, updates: Partial<FormFieldConfig>) => {
    setFields(prev => prev.map((field, i) => 
      i === index ? { ...field, ...updates } : field
    ));
  }, []);

  // Remove field
  const handleRemoveField = useCallback((index: number) => {
    setFields(prev => prev.filter((_, i) => i !== index));
    setSelectedFieldIndex(null);
  }, []);

  // Update form config
  const handleFormConfigUpdate = useCallback((updates: Partial<DynamicForm>) => {
    setFormConfig(prev => ({ ...prev, ...updates }));
  }, []);

  // Save form
  const handleSave = useCallback(() => {
    const finalForm: DynamicForm = {
      ...formConfig,
      id: form?.id || `form_${Date.now()}`,
      fields: fields.map(({ tempId, ...field }) => field),
      tenantId: customerProfile?.tenantId || 'default',
      createdAt: form?.createdAt || new Date(),
      updatedAt: new Date(),
    } as DynamicForm;

    onSave(finalForm);
  }, [formConfig, fields, form?.id, form?.createdAt, customerProfile?.tenantId, onSave]);

  // Preview form
  const handlePreview = useCallback(() => {
    const previewForm: DynamicForm = {
      ...formConfig,
      fields: fields.map(({ tempId, ...field }) => field),
    } as DynamicForm;

    if (onPreview) {
      onPreview(previewForm);
    }
    setPreviewMode(true);
  }, [formConfig, fields, onPreview]);

  // Field configuration panel
  const renderFieldConfig = () => {
    if (selectedFieldIndex === null || !fields[selectedFieldIndex]) return null;

    const field = fields[selectedFieldIndex];

    return (
      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Field Configuration
          </Typography>

          <Stack spacing={2}>
            <TextField
              fullWidth
              label="Field Name"
              value={field.name}
              onChange={(e) => handleUpdateField(selectedFieldIndex, { 
                name: e.target.value,
                id: generateFieldId(e.target.value),
              })}
            />

            <TextField
              fullWidth
              label="Field Label"
              value={field.label}
              onChange={(e) => handleUpdateField(selectedFieldIndex, { label: e.target.value })}
            />

            <TextField
              fullWidth
              label="Description"
              value={field.description}
              onChange={(e) => handleUpdateField(selectedFieldIndex, { description: e.target.value })}
              multiline
              rows={2}
            />

            <TextField
              fullWidth
              label="Placeholder"
              value={field.placeholder}
              onChange={(e) => handleUpdateField(selectedFieldIndex, { placeholder: e.target.value })}
            />

            <FormControlLabel
              control={
                <Switch
                  checked={field.required}
                  onChange={(e) => handleUpdateField(selectedFieldIndex, { required: e.target.checked })}
                />
              }
              label="Required Field"
            />

            {/* Field Options for select/radio/checkbox */}
            {(field.type === 'select' || field.type === 'multiselect' || field.type === 'radio') && (
              <Box>
                <Typography variant="body2" sx={{ mb: 1 }}>Options:</Typography>
                {field.options?.map((option, optionIndex) => (
                  <Box key={optionIndex} sx={{ display: 'flex', gap: 1, mb: 1 }}>
                    <TextField
                      size="small"
                      label="Value"
                      value={option.value}
                      onChange={(e) => {
                        const newOptions = [...(field.options || [])];
                        newOptions[optionIndex] = { ...option, value: e.target.value };
                        handleUpdateField(selectedFieldIndex, { options: newOptions });
                      }}
                    />
                    <TextField
                      size="small"
                      label="Label"
                      value={option.label}
                      onChange={(e) => {
                        const newOptions = [...(field.options || [])];
                        newOptions[optionIndex] = { ...option, label: e.target.value };
                        handleUpdateField(selectedFieldIndex, { options: newOptions });
                      }}
                    />
                    <IconButton 
                      size="small" 
                      onClick={() => {
                        const newOptions = field.options?.filter((_, i) => i !== optionIndex) || [];
                        handleUpdateField(selectedFieldIndex, { options: newOptions });
                      }}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                ))}
                <Button
                  size="small"
                  startIcon={<AddIcon />}
                  onClick={() => {
                    const newOptions = [...(field.options || []), { value: '', label: '' }];
                    handleUpdateField(selectedFieldIndex, { options: newOptions });
                  }}
                >
                  Add Option
                </Button>
              </Box>
            )}

            {/* Conditional Logic */}
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="body2">Conditional Logic</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  <TextField
                    fullWidth
                    label="Show If (JavaScript expression)"
                    value={field.conditionalLogic?.showIf || ''}
                    onChange={(e) => handleUpdateField(selectedFieldIndex, {
                      conditionalLogic: {
                        ...field.conditionalLogic,
                        showIf: e.target.value,
                      },
                    })}
                    placeholder="field1 === 'value' && field2 > 10"
                  />
                  <TextField
                    fullWidth
                    label="Required If (JavaScript expression)"
                    value={field.conditionalLogic?.requiredIf || ''}
                    onChange={(e) => handleUpdateField(selectedFieldIndex, {
                      conditionalLogic: {
                        ...field.conditionalLogic,
                        requiredIf: e.target.value,
                      },
                    })}
                  />
                </Stack>
              </AccordionDetails>
            </Accordion>

            {/* Validation Rules */}
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="body2">Validation Rules</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  {field.validation.map((rule, ruleIndex) => (
                    <Box key={ruleIndex} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                      <FormControl size="small">
                        <Select
                          value={rule.type}
                          onChange={(e) => {
                            const newValidation = [...field.validation];
                            newValidation[ruleIndex] = { ...rule, type: e.target.value as any };
                            handleUpdateField(selectedFieldIndex, { validation: newValidation });
                          }}
                        >
                          {validationTypes.map((type) => (
                            <MenuItem key={type.value} value={type.value}>
                              {type.label}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      {validationTypes.find(t => t.value === rule.type)?.hasValue && (
                        <TextField
                          size="small"
                          label="Value"
                          value={rule.value || ''}
                          onChange={(e) => {
                            const newValidation = [...field.validation];
                            newValidation[ruleIndex] = { ...rule, value: e.target.value };
                            handleUpdateField(selectedFieldIndex, { validation: newValidation });
                          }}
                        />
                      )}
                      <TextField
                        size="small"
                        label="Error Message"
                        value={rule.message}
                        onChange={(e) => {
                          const newValidation = [...field.validation];
                          newValidation[ruleIndex] = { ...rule, message: e.target.value };
                          handleUpdateField(selectedFieldIndex, { validation: newValidation });
                        }}
                      />
                      <IconButton 
                        size="small"
                        onClick={() => {
                          const newValidation = field.validation.filter((_, i) => i !== ruleIndex);
                          handleUpdateField(selectedFieldIndex, { validation: newValidation });
                        }}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  ))}
                  <Button
                    size="small"
                    startIcon={<AddIcon />}
                    onClick={() => {
                      const newValidation = [...field.validation, {
                        type: 'required',
                        message: 'This field is required',
                      }];
                      handleUpdateField(selectedFieldIndex, { validation: newValidation });
                    }}
                  >
                    Add Validation Rule
                  </Button>
                </Stack>
              </AccordionDetails>
            </Accordion>
          </Stack>
        </CardContent>
      </Card>
    );
  };

  // Form preview
  const renderFormPreview = () => {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Form Preview
          </Typography>
          <LocalizationProvider dateAdapter={AdapterDateFns}>
            <Stack spacing={3}>
              {fields.map((field, index) => {
                switch (field.type) {
                  case 'text':
                  case 'email':
                  case 'phone':
                    return (
                      <TextField
                        key={field.tempId}
                        fullWidth
                        label={field.label}
                        placeholder={field.placeholder}
                        helperText={field.description}
                        required={field.required}
                        type={field.type}
                      />
                    );
                  
                  case 'number':
                    return (
                      <TextField
                        key={field.tempId}
                        fullWidth
                        type="number"
                        label={field.label}
                        placeholder={field.placeholder}
                        helperText={field.description}
                        required={field.required}
                      />
                    );
                  
                  case 'textarea':
                    return (
                      <TextField
                        key={field.tempId}
                        fullWidth
                        multiline
                        rows={4}
                        label={field.label}
                        placeholder={field.placeholder}
                        helperText={field.description}
                        required={field.required}
                      />
                    );
                  
                  case 'select':
                    return (
                      <FormControl key={field.tempId} fullWidth required={field.required}>
                        <InputLabel>{field.label}</InputLabel>
                        <Select label={field.label}>
                          {field.options?.map((option) => (
                            <MenuItem key={option.value} value={option.value}>
                              {option.label}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    );
                  
                  case 'multiselect':
                    return (
                      <Autocomplete
                        key={field.tempId}
                        multiple
                        options={field.options || []}
                        getOptionLabel={(option) => option.label}
                        renderInput={(params) => (
                          <TextField
                            {...params}
                            label={field.label}
                            helperText={field.description}
                            required={field.required}
                          />
                        )}
                      />
                    );
                  
                  case 'checkbox':
                    return (
                      <FormControlLabel
                        key={field.tempId}
                        control={<Checkbox />}
                        label={field.label}
                        required={field.required}
                      />
                    );
                  
                  case 'radio':
                    return (
                      <Box key={field.tempId}>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          {field.label} {field.required && '*'}
                        </Typography>
                        <RadioGroup>
                          {field.options?.map((option) => (
                            <FormControlLabel
                              key={option.value}
                              value={option.value}
                              control={<Radio />}
                              label={option.label}
                            />
                          ))}
                        </RadioGroup>
                        {field.description && (
                          <Typography variant="caption" color="text.secondary">
                            {field.description}
                          </Typography>
                        )}
                      </Box>
                    );
                  
                  case 'date':
                    return (
                      <DateTimePicker
                        key={field.tempId}
                        label={field.label}
                        renderInput={(props) => (
                          <TextField
                            {...props}
                            fullWidth
                            helperText={field.description}
                            required={field.required}
                          />
                        )}
                      />
                    );
                  
                  case 'file':
                    return (
                      <Box key={field.tempId}>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          {field.label} {field.required && '*'}
                        </Typography>
                        <Button variant="outlined" component="label">
                          Choose File
                          <input type="file" hidden />
                        </Button>
                        {field.description && (
                          <Typography variant="caption" color="text.secondary" display="block">
                            {field.description}
                          </Typography>
                        )}
                      </Box>
                    );
                  
                  default:
                    return (
                      <Alert key={field.tempId} severity="warning">
                        Unknown field type: {field.type}
                      </Alert>
                    );
                }
              })}
              
              <Divider />
              
              <Box sx={{ textAlign: formConfig.layout?.submitButton.position || 'center' }}>
                <Button variant="contained" size="large">
                  {formConfig.layout?.submitButton.text || 'Submit'}
                </Button>
              </Box>
            </Stack>
          </LocalizationProvider>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box className={className}>
      {/* Header */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h5" fontWeight={600}>
            Dynamic Form Builder
          </Typography>
          <Stack direction="row" spacing={2}>
            <Button
              variant="outlined"
              startIcon={<PreviewIcon />}
              onClick={handlePreview}
              disabled={fields.length === 0}
            >
              Preview
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
            >
              Save Form
            </Button>
          </Stack>
        </Box>

        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Form Name"
              value={formConfig.name}
              onChange={(e) => handleFormConfigUpdate({ name: e.target.value })}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Version"
              value={formConfig.version}
              onChange={(e) => handleFormConfigUpdate({ version: e.target.value })}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Autocomplete
              multiple
              options={['enterprise', 'mid-market', 'small-business', 'individual']}
              value={formConfig.customerType || []}
              onChange={(_, value) => handleFormConfigUpdate({ customerType: value })}
              renderInput={(params) => (
                <TextField {...params} label="Customer Types" />
              )}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              multiline
              rows={2}
              label="Description"
              value={formConfig.description}
              onChange={(e) => handleFormConfigUpdate({ description: e.target.value })}
            />
          </Grid>
        </Grid>
      </Paper>

      <Grid container spacing={3}>
        {/* Field Types Palette */}
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Field Types
              </Typography>
              <Stack spacing={1}>
                {fieldTypes.map((fieldType) => (
                  <Button
                    key={fieldType.value}
                    variant="outlined"
                    size="small"
                    startIcon={<AddIcon />}
                    onClick={() => handleAddField(fieldType.value)}
                    sx={{ justifyContent: 'flex-start' }}
                  >
                    {fieldType.label}
                  </Button>
                ))}
              </Stack>
            </CardContent>
          </Card>

          {/* Field Configuration */}
          {selectedFieldIndex !== null && (
            <Box sx={{ mt: 2 }}>
              {renderFieldConfig()}
            </Box>
          )}
        </Grid>

        {/* Form Builder Area */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Form Fields ({fields.length})
              </Typography>
              
              {fields.length === 0 ? (
                <Alert severity="info">
                  Add fields from the field types panel to start building your form.
                </Alert>
              ) : (
                <Stack spacing={2}>
                  {fields.map((field, index) => (
                    <Paper
                      key={field.tempId}
                      elevation={selectedFieldIndex === index ? 3 : 1}
                      sx={{
                        p: 2,
                        cursor: 'pointer',
                        border: selectedFieldIndex === index ? `2px solid ${theme.palette.primary.main}` : '1px solid transparent',
                        '&:hover': { elevation: 2 },
                      }}
                      onClick={() => setSelectedFieldIndex(index)}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <DragIcon sx={{ color: 'text.secondary' }} />
                          <Box>
                            <Typography variant="body1" fontWeight={600}>
                              {field.label}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {field.type} • {field.name}
                            </Typography>
                          </Box>
                        </Box>
                        <Stack direction="row" spacing={1}>
                          {field.required && <Chip label="Required" size="small" color="error" />}
                          {field.validation.length > 0 && (
                            <Chip label={`${field.validation.length} rules`} size="small" />
                          )}
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemoveField(index);
                            }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Stack>
                      </Box>
                    </Paper>
                  ))}
                </Stack>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Form Preview */}
        <Grid item xs={12} md={3}>
          {renderFormPreview()}
        </Grid>
      </Grid>
    </Box>
  );
}

export default DynamicFormBuilder;