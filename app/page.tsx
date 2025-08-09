'use client';

import React from 'react';
import { redirect } from 'next/navigation';
import { Box, Typography, Card, CardContent, Grid, Chip, Alert } from '@mui/material';
import { Security as SecurityIcon, Shield as ShieldIcon } from '@mui/icons-material';
import { AppLayout } from './components/layout/app-layout';
import { useAuthStore } from './lib/store';

export default function HomePage() {
  const auth = useAuthStore();

  // Redirect to login if not authenticated
  if (!auth.isAuthenticated) {
    redirect('/login');
  }

  return (
    <AppLayout>
      <Box>
        {/* Page Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 600 }}>
            Welcome to iSECTECH Protect
          </Typography>
          <Typography variant="body1" color="text.secondary" gutterBottom>
            Your cybersecurity command center is ready. Navigate using the sidebar to access all security features.
          </Typography>
          
          {auth.user && (
            <Box sx={{ mt: 2, display: 'flex', gap: 1, alignItems: 'center' }}>
              <Chip
                icon={<SecurityIcon />}
                label={`Clearance: ${auth.securityClearance}`}
                color="primary"
                variant="outlined"
              />
              <Chip
                icon={<ShieldIcon />}
                label={`Role: ${auth.user.role.replace('_', ' ')}`}
                color="secondary"
                variant="outlined"
              />
            </Box>
          )}
        </Box>

        {/* Status Cards */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  System Status
                </Typography>
                <Typography variant="h4" color="success.main">
                  Operational
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  All systems functioning normally
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  Security Level
                </Typography>
                <Typography variant="h4" color="warning.main">
                  Elevated
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Enhanced monitoring active
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  Active Alerts
                </Typography>
                <Typography variant="h4" color="error.main">
                  24
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Requires immediate attention
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  Compliance Score
                </Typography>
                <Typography variant="h4" color="info.main">
                  87%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Meeting regulatory standards
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Information Alert */}
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>Development Notice:</strong> This is the iSECTECH Protect cybersecurity dashboard. 
            The full dashboard with real-time threat monitoring, analytics, and security controls is currently being built.
          </Typography>
        </Alert>

        {/* Quick Access Cards */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Dashboard
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Real-time security monitoring, threat detection, and incident response dashboard 
                  with advanced analytics and MITRE ATT&CK framework integration.
                </Typography>
                <Typography variant="body2" color="primary">
                  → Navigate to Security Center in the sidebar
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Asset Management
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Comprehensive asset inventory, vulnerability management, and network discovery 
                  with automated security assessment capabilities.
                </Typography>
                <Typography variant="body2" color="primary">
                  → Navigate to Asset Management in the sidebar
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Compliance Management
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Automated compliance monitoring for NIST, ISO 27001, SOC2, PCI DSS, and other 
                  regulatory frameworks with continuous assessment.
                </Typography>
                <Typography variant="body2" color="primary">
                  → Navigate to Compliance in the sidebar
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Analytics
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Advanced security analytics, behavioral analysis, and predictive threat modeling 
                  with machine learning-powered insights.
                </Typography>
                <Typography variant="body2" color="primary">
                  → Navigate to Analytics & Reports in the sidebar
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </AppLayout>
  );
}
