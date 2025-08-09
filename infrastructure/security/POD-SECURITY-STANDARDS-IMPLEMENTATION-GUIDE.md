# Pod Security Standards and Container Hardening Implementation Guide

**Author:** Claude Code - iSECTECH Infrastructure Team  
**Version:** 1.0.0  
**Last Updated:** January 8, 2025  
**Classification:** Internal Use

## Table of Contents

1. [Overview](#overview)
2. [Pod Security Standards Profiles](#pod-security-standards-profiles)
3. [Security Context Implementation](#security-context-implementation)
4. [OPA Gatekeeper Policy Enforcement](#opa-gatekeeper-policy-enforcement)
5. [Privileged Workload Management](#privileged-workload-management)
6. [Compliance Verification](#compliance-verification)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Best Practices](#best-practices)

## Overview

This document provides comprehensive guidance for implementing Pod Security Standards (PSS) and container hardening across the iSECTECH Kubernetes infrastructure. The implementation ensures all containerized workloads adhere to security best practices while maintaining operational functionality.

### Implementation Goals

- **Zero-Trust Security Model**: Every container runs with minimal required privileges
- **Defense in Depth**: Multiple layers of security controls
- **Compliance Automation**: Automated enforcement and monitoring
- **Operational Excellence**: Minimal impact on development workflows

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Admission Controllers                       │
├─────────────────────────────────────────────────────────────┤
│ Pod Security Standards │ OPA Gatekeeper │ Admission Webhooks │
├─────────────────────────────────────────────────────────────┤
│                    Runtime Security                         │
├─────────────────────────────────────────────────────────────┤
│    Falco Runtime    │  Seccomp/AppArmor │   SELinux/PSPs   │
├─────────────────────────────────────────────────────────────┤
│                  Container Security Context                 │
├─────────────────────────────────────────────────────────────┤
│  runAsNonRoot  │  readOnlyRootFS  │  Drop ALL Capabilities  │
└─────────────────────────────────────────────────────────────┘
```

## Pod Security Standards Profiles

### Privileged Profile
**Use Case:** System components requiring host-level access  
**Namespaces:** `kube-system`, `kube-public`, `falco-system`  
**Restrictions:** None - full host access allowed

```yaml
pod-security.kubernetes.io/enforce: privileged
pod-security.kubernetes.io/audit: baseline
pod-security.kubernetes.io/warn: baseline
```

### Baseline Profile
**Use Case:** Standard applications with minimal host access  
**Namespaces:** `kong-system`, `monitoring`, `development`  
**Key Restrictions:**
- No privileged containers
- No host network/PID/IPC access
- Limited volume types
- No privilege escalation

```yaml
pod-security.kubernetes.io/enforce: baseline
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted
```

### Restricted Profile
**Use Case:** Production applications with maximum security  
**Namespaces:** All production application namespaces  
**Key Restrictions:**
- Must run as non-root
- ReadOnly root filesystem
- Drop ALL capabilities
- RuntimeDefault seccomp profile
- No privilege escalation

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted
```

## Security Context Implementation

### Standard Restricted Security Context

Use this configuration for all production application workloads:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534  # nobody user
        runAsGroup: 65534
        fsGroup: 65534
        fsGroupChangePolicy: "OnRootMismatch"
        seccompProfile:
          type: RuntimeDefault
        supplementalGroups: []
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
          runAsGroup: 65534
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: var-cache
          mountPath: /var/cache/app
      volumes:
      - name: tmp
        emptyDir: {}
      - name: var-cache
        emptyDir: {}
```

### Security Context for Special Use Cases

#### Database Workloads
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 999  # postgres/mysql user
  runAsGroup: 999
  fsGroup: 999
  seccompProfile:
    type: RuntimeDefault
containers:
- securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    readOnlyRootFilesystem: false  # DB needs write access
    runAsNonRoot: true
    runAsUser: 999
```

#### Web Servers (Non-Root)
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
containers:
- securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
      add: ["NET_BIND_SERVICE"]  # If binding to port 80/443
    readOnlyRootFilesystem: true
```

### Security Monitoring Agents (Controlled Exception)

For security monitoring tools that require elevated privileges:

```yaml
securityContext:
  runAsNonRoot: false  # Explicitly allow root
  runAsUser: 0
  fsGroup: 0
  seccompProfile:
    type: RuntimeDefault
containers:
- securityContext:
    runAsUser: 0
    privileged: false  # Avoid privileged mode when possible
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
      add: 
        - "DAC_READ_SEARCH"  # Read restricted files
        - "DAC_OVERRIDE"     # Override file permissions
    readOnlyRootFilesystem: false
```

## OPA Gatekeeper Policy Enforcement

### Constraint Templates

The implementation includes comprehensive OPA Gatekeeper constraint templates:

1. **K8sRequireSecurityContext**: Enforces security context requirements
2. **K8sRequireResourceLimits**: Enforces resource limits
3. **K8sRestrictPrivileged**: Blocks privileged containers
4. **K8sRequireSeccomp**: Enforces seccomp profiles

### Constraint Deployment

```bash
# Deploy constraint templates and constraints
kubectl apply -f infrastructure/kubernetes/security-context-constraints.yaml

# Verify deployment
kubectl get constrainttemplates
kubectl get constraints

# Check violations
kubectl get constraints -o yaml | grep violation -A 5 -B 5
```

### Policy Exemptions

For workloads that require exemptions, use annotations:

```yaml
metadata:
  annotations:
    security.isectech.com/exempt: "true"
    security.isectech.com/exemption-reason: "Security monitoring agent requires root access"
    security.isectech.com/approved-by: "security-team"
    security.isectech.com/exemption-expires: "2025-06-01"
```

## Privileged Workload Management

### Approved Privileged Workloads

The following workloads are approved to run with elevated privileges:

1. **Falco DaemonSet** (`falco-system` namespace)
   - **Requirement:** Kernel-level monitoring
   - **Privileges:** `privileged: true`, host access
   - **Justification:** Runtime security monitoring

2. **SIEM Agents** (`isectech-siem-agents` namespace)
   - **Requirement:** Log file access
   - **Privileges:** `runAsUser: 0`, specific capabilities
   - **Justification:** Security event collection

3. **CNI Pods** (`kube-system` namespace)
   - **Requirement:** Network configuration
   - **Privileges:** Host network access
   - **Justification:** Cluster networking

### Privilege Minimization Process

For approved privileged workloads:

1. **Justify Requirements**: Document specific privileges needed
2. **Minimize Capabilities**: Drop all unnecessary capabilities
3. **Apply Time Limits**: Set expiration dates for exceptions
4. **Regular Reviews**: Quarterly assessment of privilege requirements
5. **Alternative Solutions**: Evaluate rootless alternatives

## Compliance Verification

### Automated Audit Script

Use the compliance audit script for regular verification:

```bash
# Run security context audit
./scripts/audit-security-context.sh

# View results
cat reports/security-compliance/security-context-summary-*.txt
```

### Continuous Monitoring

#### Prometheus Metrics
```yaml
- alert: SecurityContextViolation
  expr: security_context_violations_total > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Security context violations detected"
    description: "{{ $value }} pods are running with insecure security contexts"
```

#### Falco Rules
```yaml
- rule: Container Running in Privileged Mode
  desc: Detect privileged container
  condition: >
    spawned_process and container and
    (proc.name in (docker, runc, containerd)) and
    proc.args contains "--privileged"
  output: Privileged container detected (user=%user.name container=%container.name)
  priority: WARNING
```

### CI/CD Integration

#### Pre-deployment Validation
```yaml
# .github/workflows/security-validation.yml
- name: Security Context Validation
  run: |
    # Validate security contexts in manifests
    kube-score score manifests/*.yaml --ignore-test pod-networkpolicy
    
    # Scan for security issues
    trivy config manifests/
    
    # Custom security checks
    ./scripts/validate-security-contexts.sh manifests/
```

## Troubleshooting Guide

### Common Issues

#### 1. Pod Fails to Start with "runAsNonRoot" Error

**Error:**
```
container has runAsNonRoot and image will run as root
```

**Solution:**
```yaml
# Option 1: Set specific non-root user
securityContext:
  runAsUser: 1000
  runAsGroup: 1000

# Option 2: Build image with non-root user
# Dockerfile:
USER 1000:1000
```

#### 2. ReadOnlyRootFilesystem Write Permission Issues

**Error:**
```
failed to create directory: read-only file system
```

**Solution:**
```yaml
volumeMounts:
- name: tmp
  mountPath: /tmp
- name: var-cache
  mountPath: /var/cache/app
volumes:
- name: tmp
  emptyDir: {}
- name: var-cache
  emptyDir: {}
```

#### 3. Capability Requirements

**Error:**
```
Operation not permitted: insufficient capabilities
```

**Investigation:**
```bash
# Check required capabilities
getcap /usr/bin/binary

# Minimal capability addition
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only what's needed
```

#### 4. OPA Gatekeeper Policy Violations

**Check violations:**
```bash
kubectl get constraints -o yaml | grep -A 10 violations
```

**Temporary bypass (emergency only):**
```yaml
metadata:
  annotations:
    security.isectech.com/exempt: "true"
```

### Debugging Commands

```bash
# Check Pod Security Standards
kubectl get ns -o yaml | grep -A 5 -B 5 pod-security

# Verify security context
kubectl get pod <pod-name> -o jsonpath='{.spec.securityContext}'

# Check container security context
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].securityContext}'

# View OPA Gatekeeper status
kubectl get constraints
kubectl describe constraint security-context-restricted

# Check admission controller logs
kubectl logs -n gatekeeper-system deployment/gatekeeper-controller-manager
```

## Best Practices

### 1. Security Context Design

- **Default to Restricted**: Start with the most restrictive profile
- **Justify Exceptions**: Document all privilege requirements
- **Least Privilege**: Grant only necessary capabilities
- **Regular Audits**: Quarterly review of security contexts

### 2. Container Image Hardening

```dockerfile
# Use minimal base images
FROM gcr.io/distroless/java:11

# Create non-root user
RUN useradd -u 1000 appuser

# Set file ownership
COPY --chown=1000:1000 app.jar /app/

# Switch to non-root user
USER 1000:1000

# Set read-only volume mount points
VOLUME ["/tmp", "/var/cache/app"]
```

### 3. Development Workflow

1. **Security by Default**: Include security context in deployment templates
2. **Early Validation**: Add security checks to CI/CD pipeline
3. **Developer Training**: Ensure teams understand security requirements
4. **Exception Process**: Clear process for requesting privileged access

### 4. Monitoring and Alerting

```yaml
# Grafana Dashboard Queries
- Security Context Compliance Rate
- Privileged Container Count
- Policy Violation Trends
- Exception Expiration Tracking
```

### 5. Incident Response

**Security Context Violation Detected:**

1. **Immediate**: Block non-compliant deployments
2. **Investigation**: Analyze violation cause
3. **Remediation**: Update security context
4. **Prevention**: Improve CI/CD checks

**Privilege Escalation Detected:**

1. **Alert**: Immediate security team notification
2. **Isolate**: Network isolation of affected workloads
3. **Investigate**: Forensic analysis
4. **Remediate**: Apply security patches and rebuild

### 6. Regular Maintenance

**Weekly:**
- Run automated security audit
- Review new policy violations
- Update exemption tracking

**Monthly:**
- Review privileged workload justifications
- Update security context templates
- Test policy enforcement

**Quarterly:**
- Complete security context assessment
- Update documentation
- Security team review of exceptions

---

## Additional Resources

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/)
- [Container Security Best Practices](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [iSECTECH Security Policies](./COMPREHENSIVE-SECURITY-POLICY-FRAMEWORK.md)

---

**Document Control:**
- **Next Review:** April 8, 2025
- **Owner:** iSECTECH Security Team
- **Distribution:** Infrastructure Team, Development Teams, Security Team