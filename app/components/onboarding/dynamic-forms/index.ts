/**
 * Dynamic Forms Components Exports
 * Production-grade dynamic form system with conditional logic and validation
 */

export { DynamicFormBuilder } from './dynamic-form-builder';
export { DynamicFormRenderer } from './dynamic-form-renderer';

// Re-export component types
export type { DynamicFormBuilderProps } from './dynamic-form-builder';
export type { DynamicFormRendererProps } from './dynamic-form-renderer';

// Common interfaces for dynamic forms
export interface FormBuilderConfig {
  enablePreview: boolean;
  allowFieldReordering: boolean;
  availableFieldTypes: string[];
  validationTypes: string[];
  conditionalLogicEnabled: boolean;
}

export interface FormRendererConfig {
  autoSave: boolean;
  showProgress: boolean;
  allowSectionNavigation: boolean;
  validateOnChange: boolean;
  submitOnComplete: boolean;
}

export default {
  DynamicFormBuilder,
  DynamicFormRenderer,
};