/**
 * iSECTECH Chaos Monkey Implementation
 * Infrastructure resilience testing through automated instance termination and service disruption
 */

import { EventEmitter } from 'events';
import { promises as fs } from 'fs';
import * as cron from 'node-cron';
import * as yaml from 'js-yaml';
import { AWS } from 'aws-sdk';
import { KubernetesApi, V1Pod, V1Node } from '@kubernetes/client-node';
import axios from 'axios';

// Configuration interfaces
export interface ChaosMonkeyConfig {
  enabled: boolean;
  schedules: ChaosSchedule[];
  safetyLimits: SafetyLimits;
  targetSelectors: TargetSelector[];
  notifications: NotificationConfig;
  compliance: ComplianceConfig;
}

export interface ChaosSchedule {
  name: string;
  cronExpression: string;
  enabled: boolean;
  actions: ChaosAction[];
  environment: string[];
  businessHours: {
    enabled: boolean;
    timezone: string;
    hours: { start: number; end: number };
    weekdays: number[];
  };
}

export interface ChaosAction {
  type: 'terminate_instance' | 'stop_service' | 'network_chaos' | 'resource_chaos';
  parameters: ActionParameters;
  weight: number; // Probability weight for selection
  cooldown: number; // Minutes before same action can run again
}

export interface ActionParameters {
  target_type: 'ec2' | 'pod' | 'node' | 'service' | 'database';
  selector: {
    tags?: Record<string, string>;
    labels?: Record<string, string>;
    namespaces?: string[];
    instance_types?: string[];
    availability_zones?: string[];
  };
  blast_radius: {
    max_instances: number;
    max_percentage: number;
  };
  execution: {
    grace_period?: number; // seconds
    force?: boolean;
    drain_node?: boolean;
  };
}

export interface TargetSelector {
  name: string;
  description: string;
  enabled: boolean;
  selectors: {
    include: Record<string, string>;
    exclude: Record<string, string>;
  };
  constraints: {
    min_healthy_instances: number;
    max_terminations_per_hour: number;
    required_tags: string[];
  };
}

export interface SafetyLimits {
  maxConcurrentActions: number;
  maxActionsPerHour: number;
  maxActionsPerDay: number;
  cooldownBetweenActions: number; // minutes
  blackoutPeriods: BlackoutPeriod[];
  emergencyStop: {
    enabled: boolean;
    triggers: string[];
    alertsThreshold: number;
  };
}

export interface BlackoutPeriod {
  name: string;
  enabled: boolean;
  cronExpression: string;
  duration: number; // minutes
  reason: string;
}

export interface NotificationConfig {
  preAction: boolean;
  postAction: boolean;
  emergencyOnly: boolean;
  channels: {
    slack?: {
      webhook: string;
      channel: string;
    };
    email?: {
      recipients: string[];
    };
    pagerduty?: {
      integrationKey: string;
    };
  };
}

export interface ComplianceConfig {
  auditLogging: boolean;
  evidenceRetention: number; // days
  approvalRequired: boolean;
  complianceFrameworks: string[];
}

export interface ChaosEvent {
  eventId: string;
  timestamp: Date;
  action: ChaosAction;
  target: ChaosTarget;
  status: 'scheduled' | 'executing' | 'completed' | 'failed' | 'aborted';
  duration?: number; // milliseconds
  impact: {
    affectedInstances: string[];
    affectedServices: string[];
    estimatedDowntime: number; // seconds
  };
  metadata: {
    scheduleName: string;
    executorId: string;
    region: string;
    environment: string;
  };
  logs: string[];
  error?: string;
}

export interface ChaosTarget {
  type: string;
  identifier: string;
  region: string;
  metadata: Record<string, any>;
  healthStatus: 'healthy' | 'unhealthy' | 'unknown';
}

export class ChaosMonkey extends EventEmitter {
  private config: ChaosMonkeyConfig;
  private activeEvents: Map<string, ChaosEvent> = new Map();
  private actionHistory: ChaosEvent[] = [];
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map();
  private lastActionTime: Date | null = null;
  private actionCounters = {
    hourly: 0,
    daily: 0,
    lastHourReset: new Date(),
    lastDayReset: new Date(),
  };

  // AWS and Kubernetes clients
  private awsClients: Map<string, AWS> = new Map();
  private k8sClients: Map<string, KubernetesApi> = new Map();

  constructor(configPath: string) {
    super();
    this.loadConfig(configPath);
    this.initializeClients();
    this.setupSchedules();
    this.startSafetyMonitoring();
  }

  /**
   * Load Chaos Monkey configuration
   */
  private async loadConfig(configPath: string): Promise<void> {
    try {
      const configData = await fs.readFile(configPath, 'utf-8');
      this.config = yaml.load(configData) as ChaosMonkeyConfig;
      
      console.log('Chaos Monkey configuration loaded');
      console.log(`Enabled: ${this.config.enabled}`);
      console.log(`Schedules: ${this.config.schedules.length}`);
    } catch (error) {
      console.error('Failed to load Chaos Monkey config:', error.message);
      throw error;
    }
  }

  /**
   * Initialize AWS and Kubernetes clients
   */
  private initializeClients(): void {
    // Initialize AWS clients for different regions
    const regions = ['us-east-1', 'us-west-2', 'eu-west-1'];
    
    for (const region of regions) {
      const awsClient = new AWS({
        region,
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      });
      
      this.awsClients.set(region, awsClient);
    }

    // Initialize Kubernetes clients
    // In a real implementation, this would set up clients for different clusters
    console.log('AWS and Kubernetes clients initialized');
  }

  /**
   * Setup scheduled chaos actions
   */
  private setupSchedules(): void {
    if (!this.config.enabled) {
      console.log('Chaos Monkey is disabled');
      return;
    }

    for (const schedule of this.config.schedules) {
      if (schedule.enabled) {
        this.scheduleActions(schedule);
      }
    }
  }

  /**
   * Schedule chaos actions based on cron expression
   */
  private scheduleActions(schedule: ChaosSchedule): void {
    const task = cron.schedule(schedule.cronExpression, async () => {
      try {
        if (this.isBusinessHours(schedule)) {
          await this.executeScheduledActions(schedule);
        } else {
          console.log(`Skipping ${schedule.name} - outside business hours`);
        }
      } catch (error) {
        console.error(`Failed to execute scheduled actions for ${schedule.name}:`, error.message);
      }
    }, {
      scheduled: false,
      timezone: schedule.businessHours.timezone || 'UTC'
    });

    this.scheduledJobs.set(schedule.name, task);
    task.start();
    
    console.log(`Scheduled chaos actions: ${schedule.name} (${schedule.cronExpression})`);
  }

  /**
   * Check if current time is within business hours
   */
  private isBusinessHours(schedule: ChaosSchedule): boolean {
    if (!schedule.businessHours.enabled) {
      return true;
    }

    const now = new Date();
    const currentHour = now.getHours();
    const currentDay = now.getDay(); // 0 = Sunday, 1 = Monday, etc.

    // Check if current day is in allowed weekdays
    if (!schedule.businessHours.weekdays.includes(currentDay)) {
      return false;
    }

    // Check if current hour is within allowed hours
    const { start, end } = schedule.businessHours.hours;
    return currentHour >= start && currentHour < end;
  }

  /**
   * Execute scheduled chaos actions
   */
  private async executeScheduledActions(schedule: ChaosSchedule): Promise<void> {
    console.log(`Executing scheduled actions for: ${schedule.name}`);

    // Check safety limits
    if (!this.checkSafetyLimits()) {
      console.log('Safety limits exceeded - skipping chaos actions');
      return;
    }

    // Check for blackout periods
    if (this.isBlackoutPeriod()) {
      console.log('Currently in blackout period - skipping chaos actions');
      return;
    }

    // Select and execute a random action
    const selectedAction = this.selectAction(schedule.actions);
    if (selectedAction) {
      await this.executeAction(selectedAction, schedule);
    }
  }

  /**
   * Check safety limits before executing actions
   */
  private checkSafetyLimits(): boolean {
    const now = new Date();
    
    // Reset hourly counter if needed
    if (now.getTime() - this.actionCounters.lastHourReset.getTime() >= 3600000) {
      this.actionCounters.hourly = 0;
      this.actionCounters.lastHourReset = now;
    }

    // Reset daily counter if needed
    if (now.getTime() - this.actionCounters.lastDayReset.getTime() >= 86400000) {
      this.actionCounters.daily = 0;
      this.actionCounters.lastDayReset = now;
    }

    // Check limits
    if (this.activeEvents.size >= this.config.safetyLimits.maxConcurrentActions) {
      console.log('Max concurrent actions limit reached');
      return false;
    }

    if (this.actionCounters.hourly >= this.config.safetyLimits.maxActionsPerHour) {
      console.log('Max actions per hour limit reached');
      return false;
    }

    if (this.actionCounters.daily >= this.config.safetyLimits.maxActionsPerDay) {
      console.log('Max actions per day limit reached');
      return false;
    }

    // Check cooldown period
    if (this.lastActionTime) {
      const timeSinceLastAction = now.getTime() - this.lastActionTime.getTime();
      const cooldownMs = this.config.safetyLimits.cooldownBetweenActions * 60 * 1000;
      
      if (timeSinceLastAction < cooldownMs) {
        console.log('Still in cooldown period from last action');
        return false;
      }
    }

    return true;
  }

  /**
   * Check if currently in a blackout period
   */
  private isBlackoutPeriod(): boolean {
    for (const blackout of this.config.safetyLimits.blackoutPeriods) {
      if (blackout.enabled && this.isTimeInCronRange(blackout.cronExpression)) {
        console.log(`In blackout period: ${blackout.name} - ${blackout.reason}`);
        return true;
      }
    }
    return false;
  }

  /**
   * Check if current time matches cron expression
   */
  private isTimeInCronRange(cronExpression: string): boolean {
    // Simplified check - in reality would use a proper cron parser
    // For now, return false to allow actions
    return false;
  }

  /**
   * Select a chaos action based on weights
   */
  private selectAction(actions: ChaosAction[]): ChaosAction | null {
    if (actions.length === 0) {
      return null;
    }

    // Filter actions based on cooldown
    const availableActions = actions.filter(action => this.isActionAvailable(action));
    
    if (availableActions.length === 0) {
      console.log('No actions available (all in cooldown)');
      return null;
    }

    // Weighted random selection
    const totalWeight = availableActions.reduce((sum, action) => sum + action.weight, 0);
    let random = Math.random() * totalWeight;

    for (const action of availableActions) {
      random -= action.weight;
      if (random <= 0) {
        return action;
      }
    }

    return availableActions[0]; // Fallback
  }

  /**
   * Check if action is available (not in cooldown)
   */
  private isActionAvailable(action: ChaosAction): boolean {
    const now = new Date();
    const cooldownMs = action.cooldown * 60 * 1000;

    // Find last execution of this action type
    const lastExecution = this.actionHistory
      .filter(event => event.action.type === action.type)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())[0];

    if (!lastExecution) {
      return true; // Never executed before
    }

    return (now.getTime() - lastExecution.timestamp.getTime()) >= cooldownMs;
  }

  /**
   * Execute a chaos action
   */
  private async executeAction(action: ChaosAction, schedule: ChaosSchedule): Promise<void> {
    const eventId = `chaos-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const chaosEvent: ChaosEvent = {
      eventId,
      timestamp: new Date(),
      action,
      target: { type: '', identifier: '', region: '', metadata: {}, healthStatus: 'unknown' },
      status: 'scheduled',
      impact: {
        affectedInstances: [],
        affectedServices: [],
        estimatedDowntime: 0,
      },
      metadata: {
        scheduleName: schedule.name,
        executorId: 'chaos-monkey',
        region: process.env.AWS_REGION || 'us-east-1',
        environment: process.env.NODE_ENV || 'development',
      },
      logs: [],
    };

    this.activeEvents.set(eventId, chaosEvent);
    this.emit('actionStarted', chaosEvent);

    try {
      // Send pre-action notification
      if (this.config.notifications.preAction) {
        await this.sendNotification('pre_action', chaosEvent);
      }

      // Select target for the action
      const target = await this.selectTarget(action);
      if (!target) {
        throw new Error('No suitable target found for chaos action');
      }

      chaosEvent.target = target;
      chaosEvent.status = 'executing';
      chaosEvent.logs.push(`Selected target: ${target.type}:${target.identifier}`);

      // Execute the specific action
      await this.performAction(action, target, chaosEvent);

      chaosEvent.status = 'completed';
      chaosEvent.duration = Date.now() - chaosEvent.timestamp.getTime();
      
      // Update counters
      this.actionCounters.hourly++;
      this.actionCounters.daily++;
      this.lastActionTime = new Date();

      console.log(`Chaos action completed: ${action.type} on ${target.type}:${target.identifier}`);

    } catch (error) {
      chaosEvent.status = 'failed';
      chaosEvent.error = error.message;
      chaosEvent.logs.push(`Action failed: ${error.message}`);
      
      console.error(`Chaos action failed: ${error.message}`);
    } finally {
      // Send post-action notification
      if (this.config.notifications.postAction) {
        await this.sendNotification('post_action', chaosEvent);
      }

      // Move to history and clean up
      this.actionHistory.push(chaosEvent);
      this.activeEvents.delete(eventId);
      
      // Keep only last 1000 events in history
      if (this.actionHistory.length > 1000) {
        this.actionHistory = this.actionHistory.slice(-1000);
      }

      this.emit('actionCompleted', chaosEvent);
    }
  }

  /**
   * Select a target for the chaos action
   */
  private async selectTarget(action: ChaosAction): Promise<ChaosTarget | null> {
    const { target_type, selector } = action.parameters;

    switch (target_type) {
      case 'ec2':
        return await this.selectEC2Target(selector);
      case 'pod':
        return await this.selectPodTarget(selector);
      case 'node':
        return await this.selectNodeTarget(selector);
      case 'service':
        return await this.selectServiceTarget(selector);
      case 'database':
        return await this.selectDatabaseTarget(selector);
      default:
        throw new Error(`Unknown target type: ${target_type}`);
    }
  }

  /**
   * Select an EC2 instance target
   */
  private async selectEC2Target(selector: any): Promise<ChaosTarget | null> {
    const region = process.env.AWS_REGION || 'us-east-1';
    const ec2 = new AWS.EC2({ region });

    try {
      // Build filter from selector
      const filters: AWS.EC2.Filter[] = [];
      
      if (selector.tags) {
        for (const [key, value] of Object.entries(selector.tags)) {
          filters.push({
            Name: `tag:${key}`,
            Values: [value as string],
          });
        }
      }

      if (selector.instance_types) {
        filters.push({
          Name: 'instance-type',
          Values: selector.instance_types,
        });
      }

      if (selector.availability_zones) {
        filters.push({
          Name: 'placement-availability-zone',
          Values: selector.availability_zones,
        });
      }

      // Add filter for running instances
      filters.push({
        Name: 'instance-state-name',
        Values: ['running'],
      });

      const result = await ec2.describeInstances({ Filters: filters }).promise();
      
      const instances: any[] = [];
      if (result.Reservations) {
        for (const reservation of result.Reservations) {
          if (reservation.Instances) {
            instances.push(...reservation.Instances);
          }
        }
      }

      if (instances.length === 0) {
        console.log('No EC2 instances found matching selector');
        return null;
      }

      // Apply target selector constraints
      const validInstances = await this.filterInstancesByConstraints(instances);
      
      if (validInstances.length === 0) {
        console.log('No valid EC2 instances after applying constraints');
        return null;
      }

      // Select random instance
      const selectedInstance = validInstances[Math.floor(Math.random() * validInstances.length)];

      return {
        type: 'ec2',
        identifier: selectedInstance.InstanceId,
        region,
        metadata: {
          instanceType: selectedInstance.InstanceType,
          availabilityZone: selectedInstance.Placement?.AvailabilityZone,
          tags: selectedInstance.Tags || [],
        },
        healthStatus: 'healthy', // Assume healthy since it's running
      };

    } catch (error) {
      console.error('Failed to select EC2 target:', error.message);
      return null;
    }
  }

  /**
   * Select a Kubernetes pod target
   */
  private async selectPodTarget(selector: any): Promise<ChaosTarget | null> {
    try {
      // This would use Kubernetes client to list pods
      // For demonstration, returning a mock target
      
      const mockPods = [
        {
          metadata: {
            name: 'isectech-backend-abc123',
            namespace: 'isectech-production',
            labels: {
              app: 'isectech-backend',
              version: 'v1.2.3',
            },
          },
          status: {
            phase: 'Running',
          },
        },
        {
          metadata: {
            name: 'isectech-frontend-def456',
            namespace: 'isectech-production',
            labels: {
              app: 'isectech-frontend',
              version: 'v2.1.0',
            },
          },
          status: {
            phase: 'Running',
          },
        },
      ];

      // Filter pods by selector
      let filteredPods = mockPods;
      
      if (selector.namespaces) {
        filteredPods = filteredPods.filter(pod => 
          selector.namespaces.includes(pod.metadata.namespace)
        );
      }

      if (selector.labels) {
        filteredPods = filteredPods.filter(pod => {
          return Object.entries(selector.labels).every(([key, value]) => 
            pod.metadata.labels[key] === value
          );
        });
      }

      if (filteredPods.length === 0) {
        return null;
      }

      const selectedPod = filteredPods[Math.floor(Math.random() * filteredPods.length)];

      return {
        type: 'pod',
        identifier: selectedPod.metadata.name,
        region: 'kubernetes-cluster',
        metadata: {
          namespace: selectedPod.metadata.namespace,
          labels: selectedPod.metadata.labels,
        },
        healthStatus: selectedPod.status.phase === 'Running' ? 'healthy' : 'unhealthy',
      };

    } catch (error) {
      console.error('Failed to select pod target:', error.message);
      return null;
    }
  }

  /**
   * Select a Kubernetes node target
   */
  private async selectNodeTarget(selector: any): Promise<ChaosTarget | null> {
    // Similar implementation to pod selection but for nodes
    console.log('Selecting node target...');
    return null; // Not implemented in this demo
  }

  /**
   * Select a service target
   */
  private async selectServiceTarget(selector: any): Promise<ChaosTarget | null> {
    // Implementation for service selection
    console.log('Selecting service target...');
    return null; // Not implemented in this demo
  }

  /**
   * Select a database target
   */
  private async selectDatabaseTarget(selector: any): Promise<ChaosTarget | null> {
    // Implementation for database selection
    console.log('Selecting database target...');
    return null; // Not implemented in this demo
  }

  /**
   * Filter instances by target selector constraints
   */
  private async filterInstancesByConstraints(instances: any[]): Promise<any[]> {
    const validInstances: any[] = [];

    for (const targetSelector of this.config.targetSelectors) {
      if (!targetSelector.enabled) {
        continue;
      }

      // Check if instances match the target selector
      const matchingInstances = instances.filter(instance => 
        this.instanceMatchesSelector(instance, targetSelector)
      );

      // Apply constraints
      if (matchingInstances.length >= targetSelector.constraints.min_healthy_instances) {
        validInstances.push(...matchingInstances);
      }
    }

    // Remove duplicates
    const uniqueInstances = validInstances.filter((instance, index, self) => 
      index === self.findIndex(i => i.InstanceId === instance.InstanceId)
    );

    return uniqueInstances;
  }

  /**
   * Check if instance matches target selector
   */
  private instanceMatchesSelector(instance: any, selector: TargetSelector): boolean {
    // Check include criteria
    for (const [key, value] of Object.entries(selector.selectors.include)) {
      if (key.startsWith('tag:')) {
        const tagKey = key.substring(4);
        const tag = instance.Tags?.find((t: any) => t.Key === tagKey);
        if (!tag || tag.Value !== value) {
          return false;
        }
      }
    }

    // Check exclude criteria
    for (const [key, value] of Object.entries(selector.selectors.exclude)) {
      if (key.startsWith('tag:')) {
        const tagKey = key.substring(4);
        const tag = instance.Tags?.find((t: any) => t.Key === tagKey);
        if (tag && tag.Value === value) {
          return false;
        }
      }
    }

    // Check required tags
    for (const requiredTag of selector.constraints.required_tags) {
      const hasTag = instance.Tags?.some((tag: any) => tag.Key === requiredTag);
      if (!hasTag) {
        return false;
      }
    }

    return true;
  }

  /**
   * Perform the actual chaos action
   */
  private async performAction(
    action: ChaosAction,
    target: ChaosTarget,
    event: ChaosEvent
  ): Promise<void> {
    console.log(`Performing action: ${action.type} on ${target.type}:${target.identifier}`);

    switch (action.type) {
      case 'terminate_instance':
        await this.terminateInstance(target, action.parameters, event);
        break;
      case 'stop_service':
        await this.stopService(target, action.parameters, event);
        break;
      case 'network_chaos':
        await this.injectNetworkChaos(target, action.parameters, event);
        break;
      case 'resource_chaos':
        await this.injectResourceChaos(target, action.parameters, event);
        break;
      default:
        throw new Error(`Unknown action type: ${action.type}`);
    }
  }

  /**
   * Terminate an instance
   */
  private async terminateInstance(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    if (target.type === 'ec2') {
      await this.terminateEC2Instance(target, parameters, event);
    } else if (target.type === 'pod') {
      await this.terminatePod(target, parameters, event);
    } else {
      throw new Error(`Terminate action not supported for target type: ${target.type}`);
    }
  }

  /**
   * Terminate an EC2 instance
   */
  private async terminateEC2Instance(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    const ec2 = this.awsClients.get(target.region);
    if (!ec2) {
      throw new Error(`No AWS client available for region: ${target.region}`);
    }

    try {
      // Add grace period if specified
      if (parameters.execution?.grace_period) {
        event.logs.push(`Waiting for grace period: ${parameters.execution.grace_period} seconds`);
        await this.sleep(parameters.execution.grace_period * 1000);
      }

      const ec2Client = new AWS.EC2({ region: target.region });
      
      if (parameters.execution?.force) {
        // Force termination
        await ec2Client.terminateInstances({
          InstanceIds: [target.identifier],
          DryRun: false,
        }).promise();
        
        event.logs.push(`Force terminated EC2 instance: ${target.identifier}`);
      } else {
        // Graceful termination (stop first, then terminate)
        await ec2Client.stopInstances({
          InstanceIds: [target.identifier],
          Force: false,
        }).promise();
        
        event.logs.push(`Stopped EC2 instance: ${target.identifier}`);
        
        // Wait a bit then terminate
        await this.sleep(30000); // 30 seconds
        
        await ec2Client.terminateInstances({
          InstanceIds: [target.identifier],
        }).promise();
        
        event.logs.push(`Terminated EC2 instance: ${target.identifier}`);
      }

      event.impact.affectedInstances.push(target.identifier);
      event.impact.estimatedDowntime = 300; // 5 minutes estimated recovery time

    } catch (error) {
      throw new Error(`Failed to terminate EC2 instance: ${error.message}`);
    }
  }

  /**
   * Terminate a Kubernetes pod
   */
  private async terminatePod(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    try {
      // Add grace period if specified
      if (parameters.execution?.grace_period) {
        event.logs.push(`Waiting for grace period: ${parameters.execution.grace_period} seconds`);
        await this.sleep(parameters.execution.grace_period * 1000);
      }

      // This would use Kubernetes client to delete the pod
      // kubectl delete pod ${target.identifier} -n ${namespace} --grace-period=${gracePeriod}
      
      event.logs.push(`Terminated pod: ${target.identifier}`);
      event.impact.affectedInstances.push(target.identifier);
      event.impact.estimatedDowntime = 60; // 1 minute estimated recovery time

    } catch (error) {
      throw new Error(`Failed to terminate pod: ${error.message}`);
    }
  }

  /**
   * Stop a service
   */
  private async stopService(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    try {
      // This would scale the deployment to 0 replicas
      // kubectl scale deployment ${serviceName} --replicas=0
      
      event.logs.push(`Stopped service: ${target.identifier}`);
      event.impact.affectedServices.push(target.identifier);
      event.impact.estimatedDowntime = 120; // 2 minutes estimated recovery time

    } catch (error) {
      throw new Error(`Failed to stop service: ${error.message}`);
    }
  }

  /**
   * Inject network chaos
   */
  private async injectNetworkChaos(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    try {
      // This would inject network latency, packet loss, or partitions
      // Using tools like tc (traffic control) or Chaos Engineering tools
      
      event.logs.push(`Injected network chaos on: ${target.identifier}`);
      event.impact.affectedInstances.push(target.identifier);
      event.impact.estimatedDowntime = 30; // 30 seconds estimated impact

    } catch (error) {
      throw new Error(`Failed to inject network chaos: ${error.message}`);
    }
  }

  /**
   * Inject resource chaos (CPU, memory, disk)
   */
  private async injectResourceChaos(
    target: ChaosTarget,
    parameters: ActionParameters,
    event: ChaosEvent
  ): Promise<void> {
    try {
      // This would consume CPU, memory, or disk resources
      // Using stress testing tools
      
      event.logs.push(`Injected resource chaos on: ${target.identifier}`);
      event.impact.affectedInstances.push(target.identifier);
      event.impact.estimatedDowntime = 180; // 3 minutes estimated impact

    } catch (error) {
      throw new Error(`Failed to inject resource chaos: ${error.message}`);
    }
  }

  /**
   * Start safety monitoring
   */
  private startSafetyMonitoring(): void {
    // Monitor for emergency stop conditions
    setInterval(async () => {
      if (this.config.safetyLimits.emergencyStop.enabled) {
        const shouldStop = await this.checkEmergencyStopConditions();
        if (shouldStop) {
          await this.emergencyStop();
        }
      }
    }, 60000); // Check every minute

    console.log('Safety monitoring started');
  }

  /**
   * Check emergency stop conditions
   */
  private async checkEmergencyStopConditions(): Promise<boolean> {
    try {
      // Check alert volume
      const recentAlerts = await this.getRecentAlerts();
      if (recentAlerts.length > this.config.safetyLimits.emergencyStop.alertsThreshold) {
        console.log(`High alert volume detected: ${recentAlerts.length} alerts`);
        return true;
      }

      // Check for specific emergency triggers
      for (const trigger of this.config.safetyLimits.emergencyStop.triggers) {
        const conditionMet = await this.checkEmergencyTrigger(trigger);
        if (conditionMet) {
          console.log(`Emergency trigger activated: ${trigger}`);
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error('Failed to check emergency stop conditions:', error.message);
      return false;
    }
  }

  /**
   * Check a specific emergency trigger
   */
  private async checkEmergencyTrigger(trigger: string): Promise<boolean> {
    switch (trigger) {
      case 'high_error_rate':
        return await this.checkHighErrorRate();
      case 'service_outage':
        return await this.checkServiceOutage();
      case 'database_issues':
        return await this.checkDatabaseIssues();
      default:
        return false;
    }
  }

  /**
   * Check for high error rate
   */
  private async checkHighErrorRate(): Promise<boolean> {
    try {
      // Query monitoring system for error rate
      const response = await axios.get(
        'http://prometheus.isectech.com/api/v1/query?query=rate(http_requests_total{status=~"5.."}[5m])',
        { timeout: 10000 }
      );

      const errorRate = response.data.data.result[0]?.value[1] || 0;
      return parseFloat(errorRate) > 0.1; // 10% error rate threshold
    } catch (error) {
      console.error('Failed to check error rate:', error.message);
      return false;
    }
  }

  /**
   * Check for service outage
   */
  private async checkServiceOutage(): Promise<boolean> {
    try {
      // Check critical service health endpoints
      const healthEndpoints = [
        'https://api.isectech.com/health',
        'https://app.isectech.com/health',
      ];

      for (const endpoint of healthEndpoints) {
        try {
          const response = await axios.get(endpoint, { timeout: 10000 });
          if (response.status !== 200) {
            return true;
          }
        } catch (error) {
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error('Failed to check service outage:', error.message);
      return false;
    }
  }

  /**
   * Check for database issues
   */
  private async checkDatabaseIssues(): Promise<boolean> {
    try {
      // Check database connectivity and performance
      const response = await axios.get(
        'https://api.isectech.com/health/database',
        { timeout: 10000 }
      );

      return response.status !== 200;
    } catch (error) {
      console.error('Failed to check database health:', error.message);
      return true; // Assume database issue if health check fails
    }
  }

  /**
   * Execute emergency stop
   */
  private async emergencyStop(): Promise<void> {
    console.log('🚨 EMERGENCY STOP ACTIVATED - Stopping all chaos actions');

    // Stop all scheduled jobs
    for (const [name, task] of this.scheduledJobs) {
      task.stop();
      console.log(`Stopped scheduled job: ${name}`);
    }

    // Abort all active events
    for (const [eventId, event] of this.activeEvents) {
      event.status = 'aborted';
      event.logs.push('Aborted due to emergency stop');
      console.log(`Aborted active event: ${eventId}`);
    }

    // Send emergency notification
    await this.sendEmergencyNotification();

    // Disable Chaos Monkey
    this.config.enabled = false;

    this.emit('emergencyStop', {
      timestamp: new Date(),
      reason: 'Emergency stop conditions met',
      activeEvents: Array.from(this.activeEvents.keys()),
    });
  }

  /**
   * Send emergency notification
   */
  private async sendEmergencyNotification(): Promise<void> {
    const message = {
      text: '🚨 Chaos Monkey Emergency Stop Activated',
      attachments: [
        {
          color: 'danger',
          title: 'Emergency Stop',
          fields: [
            {
              title: 'Timestamp',
              value: new Date().toISOString(),
              short: true,
            },
            {
              title: 'Active Events',
              value: this.activeEvents.size.toString(),
              short: true,
            },
            {
              title: 'Reason',
              value: 'Emergency stop conditions detected',
              short: false,
            },
          ],
        },
      ],
    };

    if (this.config.notifications.channels.slack) {
      await this.sendSlackNotification(this.config.notifications.channels.slack.webhook, message);
    }

    if (this.config.notifications.channels.email) {
      await this.sendEmailNotification(
        this.config.notifications.channels.email.recipients,
        'Chaos Monkey Emergency Stop',
        JSON.stringify(message, null, 2)
      );
    }
  }

  /**
   * Send notification about chaos action
   */
  private async sendNotification(
    type: 'pre_action' | 'post_action',
    event: ChaosEvent
  ): Promise<void> {
    if (this.config.notifications.emergencyOnly && event.status !== 'failed') {
      return;
    }

    const message = this.buildNotificationMessage(type, event);

    if (this.config.notifications.channels.slack) {
      await this.sendSlackNotification(this.config.notifications.channels.slack.webhook, message);
    }

    if (this.config.notifications.channels.email) {
      await this.sendEmailNotification(
        this.config.notifications.channels.email.recipients,
        message.subject,
        message.body
      );
    }
  }

  /**
   * Build notification message
   */
  private buildNotificationMessage(
    type: 'pre_action' | 'post_action',
    event: ChaosEvent
  ): any {
    const emoji = type === 'pre_action' ? '⚠️' : event.status === 'completed' ? '✅' : '❌';
    const title = type === 'pre_action' 
      ? `Chaos Action Starting: ${event.action.type}`
      : `Chaos Action ${event.status}: ${event.action.type}`;

    return {
      subject: title,
      body: `
Chaos Monkey Action ${type === 'pre_action' ? 'Starting' : 'Completed'}

Action: ${event.action.type}
Target: ${event.target.type}:${event.target.identifier}
Status: ${event.status}
Schedule: ${event.metadata.scheduleName}
Environment: ${event.metadata.environment}

${event.impact.affectedInstances.length > 0 ? 
  `Affected Instances: ${event.impact.affectedInstances.join(', ')}` : ''}
${event.impact.affectedServices.length > 0 ? 
  `Affected Services: ${event.impact.affectedServices.join(', ')}` : ''}

Logs:
${event.logs.join('\n')}
`,
      text: `${emoji} ${title}`,
      attachments: [
        {
          color: event.status === 'completed' ? 'good' : event.status === 'failed' ? 'danger' : 'warning',
          title: title,
          fields: [
            {
              title: 'Target',
              value: `${event.target.type}:${event.target.identifier}`,
              short: true,
            },
            {
              title: 'Status',
              value: event.status,
              short: true,
            },
            {
              title: 'Environment',
              value: event.metadata.environment,
              short: true,
            },
            {
              title: 'Duration',
              value: event.duration ? `${(event.duration / 1000).toFixed(1)}s` : 'N/A',
              short: true,
            },
          ],
          ts: Math.floor(event.timestamp.getTime() / 1000),
        },
      ],
    };
  }

  /**
   * Utility methods
   */
  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async getRecentAlerts(): Promise<any[]> {
    // Query monitoring system for recent alerts
    // This would integrate with Prometheus AlertManager or similar
    return [];
  }

  private async sendSlackNotification(webhook: string, message: any): Promise<void> {
    try {
      await axios.post(webhook, message);
    } catch (error) {
      console.error('Failed to send Slack notification:', error.message);
    }
  }

  private async sendEmailNotification(recipients: string[], subject: string, body: string): Promise<void> {
    try {
      // This would use nodemailer or similar to send emails
      console.log(`Email notification sent to: ${recipients.join(', ')}`);
      console.log(`Subject: ${subject}`);
    } catch (error) {
      console.error('Failed to send email notification:', error.message);
    }
  }

  /**
   * Public API methods
   */
  
  public enable(): void {
    this.config.enabled = true;
    this.setupSchedules();
    console.log('Chaos Monkey enabled');
  }

  public disable(): void {
    this.config.enabled = false;
    
    // Stop all scheduled jobs
    for (const [name, task] of this.scheduledJobs) {
      task.stop();
    }
    this.scheduledJobs.clear();
    
    console.log('Chaos Monkey disabled');
  }

  public getStatus(): {
    enabled: boolean;
    activeEvents: number;
    scheduledJobs: number;
    actionCounters: typeof this.actionCounters;
    lastActionTime: Date | null;
  } {
    return {
      enabled: this.config.enabled,
      activeEvents: this.activeEvents.size,
      scheduledJobs: this.scheduledJobs.size,
      actionCounters: { ...this.actionCounters },
      lastActionTime: this.lastActionTime,
    };
  }

  public getActionHistory(): ChaosEvent[] {
    return [...this.actionHistory];
  }

  public getActiveEvents(): ChaosEvent[] {
    return Array.from(this.activeEvents.values());
  }

  public async abortEvent(eventId: string): Promise<void> {
    const event = this.activeEvents.get(eventId);
    if (!event) {
      throw new Error(`Event ${eventId} not found`);
    }

    event.status = 'aborted';
    event.logs.push('Manually aborted');
    
    this.activeEvents.delete(eventId);
    this.actionHistory.push(event);
    
    console.log(`Aborted chaos event: ${eventId}`);
  }

  public async executeManualAction(action: ChaosAction): Promise<string> {
    // Create a temporary schedule for manual execution
    const manualSchedule: ChaosSchedule = {
      name: 'manual-execution',
      cronExpression: '',
      enabled: true,
      actions: [action],
      environment: [process.env.NODE_ENV || 'development'],
      businessHours: {
        enabled: false,
        timezone: 'UTC',
        hours: { start: 0, end: 24 },
        weekdays: [0, 1, 2, 3, 4, 5, 6],
      },
    };

    await this.executeAction(action, manualSchedule);
    return 'Manual action executed';
  }
}

export default ChaosMonkey;