/**
 * Alert Filters Component for iSECTECH Protect
 * Advanced filtering interface for intelligent alert management
 */

'use client';

import type { AlertFilters as AlertFiltersType } from '@/lib/api/services/alerts';
import type { AlertPriority, AlertStatus, ThreatCategory, ThreatSeverity } from '@/types';
import {
  PersonAdd as AssignIcon,
  Clear as ClearIcon,
  ExpandLess as CollapseIcon,
  DateRange as DateRangeIcon,
  ExpandMore as ExpandIcon,
  FilterList as FilterIcon,
  TrendingUp as RiskIcon,
  Search as SearchIcon,
  Security as SecurityIcon,
  Tag as TagIcon,
} from '@mui/icons-material';
import {
  Autocomplete,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Collapse,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  OutlinedInput,
  Select,
  Slider,
  Stack,
  Switch,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import React, { useCallback, useState } from 'react';

interface AlertFiltersProps {
  onFiltersChange: (filters: AlertFiltersType) => void;
  onSearchChange: (query: string) => void;
  initialFilters?: AlertFiltersType;
  compact?: boolean;
}

const statusOptions: { value: AlertStatus; label: string; color: string }[] = [
  { value: 'OPEN', label: 'Open', color: '#f44336' },
  { value: 'IN_PROGRESS', label: 'In Progress', color: '#ff9800' },
  { value: 'RESOLVED', label: 'Resolved', color: '#4caf50' },
  { value: 'CLOSED', label: 'Closed', color: '#757575' },
  { value: 'FALSE_POSITIVE', label: 'False Positive', color: '#9e9e9e' },
];

const priorityOptions: { value: AlertPriority; label: string; color: string }[] = [
  { value: 'P1', label: 'P1 - Critical', color: '#d32f2f' },
  { value: 'P2', label: 'P2 - High', color: '#f57c00' },
  { value: 'P3', label: 'P3 - Medium', color: '#fbc02d' },
  { value: 'P4', label: 'P4 - Low', color: '#388e3c' },
  { value: 'P5', label: 'P5 - Info', color: '#757575' },
];

const severityOptions: { value: ThreatSeverity; label: string; color: string }[] = [
  { value: 'CRITICAL', label: 'Critical', color: '#d32f2f' },
  { value: 'HIGH', label: 'High', color: '#f57c00' },
  { value: 'MEDIUM', label: 'Medium', color: '#fbc02d' },
  { value: 'LOW', label: 'Low', color: '#388e3c' },
];

const categoryOptions: { value: ThreatCategory; label: string }[] = [
  { value: 'MALWARE', label: 'Malware' },
  { value: 'PHISHING', label: 'Phishing' },
  { value: 'RANSOMWARE', label: 'Ransomware' },
  { value: 'APT', label: 'Advanced Persistent Threat' },
  { value: 'INSIDER_THREAT', label: 'Insider Threat' },
  { value: 'DATA_BREACH', label: 'Data Breach' },
  { value: 'DDOS', label: 'DDoS Attack' },
  { value: 'VULNERABILITY_EXPLOIT', label: 'Vulnerability Exploit' },
];

// Mock assignee options - in real app, this would come from API
const assigneeOptions = [
  'alice.johnson@isectech.com',
  'bob.smith@isectech.com',
  'carol.chen@isectech.com',
  'david.wilson@isectech.com',
  'eve.brown@isectech.com',
];

// Mock tag options - in real app, this would come from API
const tagOptions = [
  'critical-infrastructure',
  'financial-sector',
  'healthcare',
  'government',
  'automated-detection',
  'user-reported',
  'threat-hunting',
  'compliance-violation',
];

export function AlertFilters({ onFiltersChange, onSearchChange, initialFilters, compact = false }: AlertFiltersProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(!compact);
  const [localFilters, setLocalFilters] = useState<AlertFiltersType>(initialFilters || {});
  const [searchQuery, setSearchQuery] = useState('');

  const handleFilterChange = useCallback(
    (key: keyof AlertFiltersType, value: any) => {
      const newFilters = { ...localFilters, [key]: value };
      setLocalFilters(newFilters);
      onFiltersChange(newFilters);
    },
    [localFilters, onFiltersChange]
  );

  const handleClearFilter = useCallback(
    (key: keyof AlertFiltersType) => {
      const newFilters = { ...localFilters };
      delete newFilters[key];
      setLocalFilters(newFilters);
      onFiltersChange(newFilters);
    },
    [localFilters, onFiltersChange]
  );

  const handleClearAllFilters = useCallback(() => {
    setLocalFilters({});
    setSearchQuery('');
    onFiltersChange({});
    onSearchChange('');
  }, [onFiltersChange, onSearchChange]);

  const handleSearchChange = useCallback(
    (query: string) => {
      setSearchQuery(query);
      onSearchChange(query);
    },
    [onSearchChange]
  );

  const getActiveFilterCount = () => {
    return Object.keys(localFilters).length;
  };

  const renderFilterChips = () => {
    const chips: React.ReactNode[] = [];

    if (localFilters.status?.length) {
      chips.push(
        <Chip
          key="status"
          label={`Status: ${localFilters.status.length} selected`}
          onDelete={() => handleClearFilter('status')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    if (localFilters.priority?.length) {
      chips.push(
        <Chip
          key="priority"
          label={`Priority: ${localFilters.priority.length} selected`}
          onDelete={() => handleClearFilter('priority')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    if (localFilters.severity?.length) {
      chips.push(
        <Chip
          key="severity"
          label={`Severity: ${localFilters.severity.length} selected`}
          onDelete={() => handleClearFilter('severity')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    if (localFilters.assignedTo?.length) {
      chips.push(
        <Chip
          key="assignee"
          label={`Assignee: ${localFilters.assignedTo.length} selected`}
          onDelete={() => handleClearFilter('assignedTo')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    if (localFilters.dateRange) {
      chips.push(
        <Chip
          key="dateRange"
          label="Date Range Set"
          onDelete={() => handleClearFilter('dateRange')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    if (localFilters.riskScoreRange) {
      chips.push(
        <Chip
          key="riskScore"
          label={`Risk: ${localFilters.riskScoreRange.min}-${localFilters.riskScoreRange.max}`}
          onDelete={() => handleClearFilter('riskScoreRange')}
          size="small"
          color="primary"
          variant="outlined"
        />
      );
    }

    return chips;
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Card variant="outlined">
        <CardHeader
          title={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <FilterIcon />
              <Typography variant="h6">Filters</Typography>
              {getActiveFilterCount() > 0 && <Badge badgeContent={getActiveFilterCount()} color="primary" />}
            </Box>
          }
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              {getActiveFilterCount() > 0 && (
                <Button size="small" onClick={handleClearAllFilters} startIcon={<ClearIcon />} color="secondary">
                  Clear All
                </Button>
              )}
              <IconButton onClick={() => setExpanded(!expanded)}>
                {expanded ? <CollapseIcon /> : <ExpandIcon />}
              </IconButton>
            </Box>
          }
          sx={{ pb: 1 }}
        />

        {/* Active Filter Chips */}
        {getActiveFilterCount() > 0 && (
          <Box sx={{ px: 2, pb: 1 }}>
            <Stack direction="row" spacing={1} flexWrap="wrap">
              {renderFilterChips()}
            </Stack>
          </Box>
        )}

        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <CardContent>
            <Grid container spacing={3}>
              {/* Search */}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Search Alerts"
                  placeholder="Search by title, description, or alert ID..."
                  value={searchQuery}
                  onChange={(e) => handleSearchChange(e.target.value)}
                  InputProps={{
                    startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                  }}
                />
              </Grid>

              {/* Status Filter */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Status</InputLabel>
                  <Select
                    multiple
                    value={localFilters.status || []}
                    onChange={(e) => handleFilterChange('status', e.target.value)}
                    input={<OutlinedInput label="Status" />}
                    renderValue={(selected) => (
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {selected.map((value) => (
                          <Chip
                            key={value}
                            label={statusOptions.find((o) => o.value === value)?.label}
                            size="small"
                            sx={{ backgroundColor: statusOptions.find((o) => o.value === value)?.color }}
                          />
                        ))}
                      </Stack>
                    )}
                  >
                    {statusOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: '50%',
                              backgroundColor: option.color,
                            }}
                          />
                          {option.label}
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Priority Filter */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Priority</InputLabel>
                  <Select
                    multiple
                    value={localFilters.priority || []}
                    onChange={(e) => handleFilterChange('priority', e.target.value)}
                    input={<OutlinedInput label="Priority" />}
                    renderValue={(selected) => (
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {selected.map((value) => (
                          <Chip
                            key={value}
                            label={value}
                            size="small"
                            sx={{ backgroundColor: priorityOptions.find((o) => o.value === value)?.color }}
                          />
                        ))}
                      </Stack>
                    )}
                  >
                    {priorityOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: '50%',
                              backgroundColor: option.color,
                            }}
                          />
                          {option.label}
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Severity Filter */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    multiple
                    value={localFilters.severity || []}
                    onChange={(e) => handleFilterChange('severity', e.target.value)}
                    input={<OutlinedInput label="Severity" />}
                    renderValue={(selected) => (
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {selected.map((value) => (
                          <Chip
                            key={value}
                            label={value}
                            size="small"
                            sx={{ backgroundColor: severityOptions.find((o) => o.value === value)?.color }}
                          />
                        ))}
                      </Stack>
                    )}
                  >
                    {severityOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <SecurityIcon sx={{ fontSize: 16, color: option.color }} />
                          {option.label}
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Category Filter */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    multiple
                    value={localFilters.category || []}
                    onChange={(e) => handleFilterChange('category', e.target.value)}
                    input={<OutlinedInput label="Category" />}
                    renderValue={(selected) => `${selected.length} selected`}
                  >
                    {categoryOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        {option.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Assignee Filter */}
              <Grid item xs={12} sm={6}>
                <Autocomplete
                  multiple
                  options={assigneeOptions}
                  value={localFilters.assignedTo || []}
                  onChange={(_, value) => handleFilterChange('assignedTo', value)}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label="Assigned To"
                      placeholder="Select assignees..."
                      InputProps={{
                        ...params.InputProps,
                        startAdornment: (
                          <>
                            <AssignIcon sx={{ mr: 1, color: 'text.secondary' }} />
                            {params.InputProps.startAdornment}
                          </>
                        ),
                      }}
                    />
                  )}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip {...getTagProps({ index })} key={option} label={option.split('@')[0]} size="small" />
                    ))
                  }
                />
              </Grid>

              {/* Tags Filter */}
              <Grid item xs={12} sm={6}>
                <Autocomplete
                  multiple
                  options={tagOptions}
                  value={localFilters.tags || []}
                  onChange={(_, value) => handleFilterChange('tags', value)}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label="Tags"
                      placeholder="Select tags..."
                      InputProps={{
                        ...params.InputProps,
                        startAdornment: (
                          <>
                            <TagIcon sx={{ mr: 1, color: 'text.secondary' }} />
                            {params.InputProps.startAdornment}
                          </>
                        ),
                      }}
                    />
                  )}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip {...getTagProps({ index })} key={option} label={option} size="small" />
                    ))
                  }
                />
              </Grid>

              <Grid item xs={12}>
                <Divider />
              </Grid>

              {/* Date Range */}
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DateRangeIcon sx={{ fontSize: 16 }} />
                  Date Range
                </Typography>
                <Stack direction="row" spacing={2}>
                  <DatePicker
                    label="Start Date"
                    value={localFilters.dateRange?.start || null}
                    onChange={(date) => {
                      if (date) {
                        handleFilterChange('dateRange', {
                          ...localFilters.dateRange,
                          start: date,
                        });
                      }
                    }}
                    slotProps={{ textField: { size: 'small' } }}
                  />
                  <DatePicker
                    label="End Date"
                    value={localFilters.dateRange?.end || null}
                    onChange={(date) => {
                      if (date) {
                        handleFilterChange('dateRange', {
                          ...localFilters.dateRange,
                          end: date,
                        });
                      }
                    }}
                    slotProps={{ textField: { size: 'small' } }}
                  />
                </Stack>
              </Grid>

              {/* Risk Score Range */}
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <RiskIcon sx={{ fontSize: 16 }} />
                  Risk Score Range
                </Typography>
                <Box sx={{ px: 2 }}>
                  <Slider
                    value={[localFilters.riskScoreRange?.min || 0, localFilters.riskScoreRange?.max || 100]}
                    onChange={(_, value) => {
                      const [min, max] = value as number[];
                      handleFilterChange('riskScoreRange', { min, max });
                    }}
                    valueLabelDisplay="auto"
                    min={0}
                    max={100}
                    marks={[
                      { value: 0, label: '0' },
                      { value: 25, label: '25' },
                      { value: 50, label: '50' },
                      { value: 75, label: '75' },
                      { value: 100, label: '100' },
                    ]}
                  />
                </Box>
              </Grid>

              {/* Boolean Filters */}
              <Grid item xs={12}>
                <Stack direction="row" spacing={3} flexWrap="wrap">
                  <FormControlLabel
                    control={
                      <Switch
                        checked={localFilters.hasInvestigationNotes || false}
                        onChange={(e) => handleFilterChange('hasInvestigationNotes', e.target.checked)}
                      />
                    }
                    label="Has Investigation Notes"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={localFilters.slaBreached || false}
                        onChange={(e) => handleFilterChange('slaBreached', e.target.checked)}
                      />
                    }
                    label="SLA Breached"
                  />
                </Stack>
              </Grid>
            </Grid>
          </CardContent>
        </Collapse>
      </Card>
    </LocalizationProvider>
  );
}

export default AlertFilters;
