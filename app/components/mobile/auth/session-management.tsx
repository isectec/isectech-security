'use client';

import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { 
  Shield, 
  Clock, 
  AlertTriangle, 
  Check, 
  LogOut,
  Pause,
  Play,
  Settings,
  Activity,
  Smartphone,
  Globe
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';

/**
 * Session Management Component
 * Production-grade session handling with timeout, activity tracking, and security controls
 * Implements secure session lifecycle management for mobile applications
 */

export interface SessionConfig {
  defaultTimeout: number; // milliseconds
  warningThreshold: number; // milliseconds before timeout to show warning
  maxIdleTime: number; // milliseconds
  extendOnActivity: boolean;
  trackActivity: boolean;
  secureLogout: boolean;
  multiTabSync: boolean;
  sessionStorageKey: string;
  heartbeatInterval: number;
}

export interface SessionState {
  isActive: boolean;
  startTime: number;
  lastActivity: number;
  expiresAt: number;
  timeRemaining: number;
  isIdle: boolean;
  activityCount: number;
  warnings: number;
  sessionId: string;
  deviceId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface ActivityEvent {
  type: 'mouse' | 'keyboard' | 'touch' | 'focus' | 'visibility' | 'heartbeat';
  timestamp: number;
  metadata?: any;
}

export interface SessionEvent {
  type: 'start' | 'extend' | 'warning' | 'timeout' | 'logout' | 'activity';
  timestamp: number;
  sessionId: string;
  data?: any;
}

interface SessionManagementProps {
  config: SessionConfig;
  onSessionStart?: (session: SessionState) => void;
  onSessionTimeout?: (session: SessionState) => void;
  onSessionWarning?: (session: SessionState, timeRemaining: number) => void;
  onSessionExtended?: (session: SessionState) => void;
  onActivityDetected?: (activity: ActivityEvent) => void;
  onSecureLogout?: () => void;
  autoStart?: boolean;
  children?: React.ReactNode;
}

// Session management context
interface SessionContextValue {
  session: SessionState | null;
  startSession: () => void;
  extendSession: (duration?: number) => void;
  endSession: () => void;
  pauseSession: () => void;
  resumeSession: () => void;
  isSessionActive: () => boolean;
  getTimeRemaining: () => number;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export const useSession = () => {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useSession must be used within a SessionProvider');
  }
  return context;
};

// Default session configuration
const DEFAULT_CONFIG: SessionConfig = {
  defaultTimeout: 1800000, // 30 minutes
  warningThreshold: 300000, // 5 minutes
  maxIdleTime: 900000, // 15 minutes
  extendOnActivity: true,
  trackActivity: true,
  secureLogout: true,
  multiTabSync: true,
  sessionStorageKey: 'isectech_session',
  heartbeatInterval: 60000 // 1 minute
};

export function SessionManagement({
  config = DEFAULT_CONFIG,
  onSessionStart,
  onSessionTimeout,
  onSessionWarning,
  onSessionExtended,
  onActivityDetected,
  onSecureLogout,
  autoStart = true,
  children
}: SessionManagementProps) {
  const [session, setSession] = useState<SessionState | null>(null);
  const [isConfigVisible, setIsConfigVisible] = useState(false);
  const [localConfig, setLocalConfig] = useState(config);
  const [recentActivity, setRecentActivity] = useState<ActivityEvent[]>([]);
  const [sessionEvents, setSessionEvents] = useState<SessionEvent[]>([]);
  
  const timeoutRef = useRef<NodeJS.Timeout>();
  const warningTimeoutRef = useRef<NodeJS.Timeout>();
  const heartbeatRef = useRef<NodeJS.Timeout>();
  const activityListenersRef = useRef<(() => void)[]>([]);

  /**
   * Generate unique session ID
   */
  const generateSessionId = useCallback((): string => {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  /**
   * Log session event
   */
  const logSessionEvent = useCallback((event: Omit<SessionEvent, 'timestamp'>) => {
    const sessionEvent: SessionEvent = {
      ...event,
      timestamp: Date.now()
    };
    
    setSessionEvents(prev => [sessionEvent, ...prev.slice(0, 99)]); // Keep last 100 events
  }, []);

  /**
   * Record activity event
   */
  const recordActivity = useCallback((event: Omit<ActivityEvent, 'timestamp'>) => {
    const activityEvent: ActivityEvent = {
      ...event,
      timestamp: Date.now()
    };

    setRecentActivity(prev => [activityEvent, ...prev.slice(0, 49)]); // Keep last 50 activities
    onActivityDetected?.(activityEvent);

    // Update session last activity if session is active
    if (session && session.isActive) {
      setSession(prev => prev ? {
        ...prev,
        lastActivity: Date.now(),
        activityCount: prev.activityCount + 1,
        isIdle: false
      } : prev);

      // Extend session if configured to do so
      if (localConfig.extendOnActivity && !session.isIdle) {
        extendSession();
      }
    }
  }, [session, localConfig.extendOnActivity, onActivityDetected]);

  /**
   * Setup activity listeners
   */
  const setupActivityListeners = useCallback(() => {
    if (!localConfig.trackActivity) return;

    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    const activityHandler = (event: Event) => {
      recordActivity({
        type: event.type.includes('mouse') ? 'mouse' : 
              event.type.includes('key') ? 'keyboard' : 
              event.type.includes('touch') ? 'touch' : 'mouse',
        metadata: {
          eventType: event.type,
          target: event.target?.constructor.name
        }
      });
    };

    events.forEach(eventType => {
      document.addEventListener(eventType, activityHandler, { passive: true });
      activityListenersRef.current.push(() => {
        document.removeEventListener(eventType, activityHandler);
      });
    });

    // Focus/blur events
    const focusHandler = () => recordActivity({ type: 'focus' });
    const blurHandler = () => recordActivity({ type: 'focus', metadata: { focused: false } });
    
    window.addEventListener('focus', focusHandler);
    window.addEventListener('blur', blurHandler);
    
    activityListenersRef.current.push(() => {
      window.removeEventListener('focus', focusHandler);
      window.removeEventListener('blur', blurHandler);
    });

    // Visibility change
    const visibilityHandler = () => {
      recordActivity({
        type: 'visibility',
        metadata: { hidden: document.hidden }
      });
    };
    
    document.addEventListener('visibilitychange', visibilityHandler);
    activityListenersRef.current.push(() => {
      document.removeEventListener('visibilitychange', visibilityHandler);
    });
  }, [localConfig.trackActivity, recordActivity]);

  /**
   * Start session
   */
  const startSession = useCallback(() => {
    const now = Date.now();
    const sessionId = generateSessionId();
    
    const newSession: SessionState = {
      isActive: true,
      startTime: now,
      lastActivity: now,
      expiresAt: now + localConfig.defaultTimeout,
      timeRemaining: localConfig.defaultTimeout,
      isIdle: false,
      activityCount: 0,
      warnings: 0,
      sessionId,
      deviceId: navigator.userAgent.replace(/[^a-zA-Z0-9]/g, '').substr(0, 16),
      userAgent: navigator.userAgent
    };

    setSession(newSession);
    setupActivityListeners();
    scheduleTimeout(newSession);
    startHeartbeat();

    // Store session in localStorage for multi-tab sync
    if (localConfig.multiTabSync) {
      localStorage.setItem(localConfig.sessionStorageKey, JSON.stringify({
        sessionId,
        startTime: now,
        expiresAt: newSession.expiresAt
      }));
    }

    logSessionEvent({
      type: 'start',
      sessionId,
      data: { timeout: localConfig.defaultTimeout }
    });

    onSessionStart?.(newSession);
  }, [localConfig, generateSessionId, setupActivityListeners, onSessionStart]);

  /**
   * Schedule session timeout
   */
  const scheduleTimeout = useCallback((sessionState: SessionState) => {
    // Clear existing timeouts
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (warningTimeoutRef.current) clearTimeout(warningTimeoutRef.current);

    const now = Date.now();
    const timeUntilTimeout = sessionState.expiresAt - now;
    const timeUntilWarning = timeUntilTimeout - localConfig.warningThreshold;

    // Schedule warning
    if (timeUntilWarning > 0) {
      warningTimeoutRef.current = setTimeout(() => {
        if (session && session.isActive) {
          const updatedSession = {
            ...session,
            warnings: session.warnings + 1
          };
          setSession(updatedSession);
          
          logSessionEvent({
            type: 'warning',
            sessionId: session.sessionId,
            data: { timeRemaining: localConfig.warningThreshold }
          });

          onSessionWarning?.(updatedSession, localConfig.warningThreshold);
        }
      }, timeUntilWarning);
    }

    // Schedule timeout
    if (timeUntilTimeout > 0) {
      timeoutRef.current = setTimeout(() => {
        if (session && session.isActive) {
          endSession(true);
        }
      }, timeUntilTimeout);
    }
  }, [localConfig.warningThreshold, session, onSessionWarning]);

  /**
   * Extend session
   */
  const extendSession = useCallback((duration?: number) => {
    if (!session || !session.isActive) return;

    const extensionTime = duration || localConfig.defaultTimeout;
    const now = Date.now();
    
    const extendedSession = {
      ...session,
      expiresAt: now + extensionTime,
      timeRemaining: extensionTime,
      lastActivity: now
    };

    setSession(extendedSession);
    scheduleTimeout(extendedSession);

    logSessionEvent({
      type: 'extend',
      sessionId: session.sessionId,
      data: { extension: extensionTime }
    });

    onSessionExtended?.(extendedSession);
  }, [session, localConfig.defaultTimeout, scheduleTimeout, onSessionExtended]);

  /**
   * End session
   */
  const endSession = useCallback((isTimeout = false) => {
    if (!session) return;

    // Clear timers
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (warningTimeoutRef.current) clearTimeout(warningTimeoutRef.current);
    if (heartbeatRef.current) clearTimeout(heartbeatRef.current);

    // Remove activity listeners
    activityListenersRef.current.forEach(cleanup => cleanup());
    activityListenersRef.current = [];

    // Clear session storage
    if (localConfig.multiTabSync) {
      localStorage.removeItem(localConfig.sessionStorageKey);
    }

    const endedSession = {
      ...session,
      isActive: false,
      timeRemaining: 0
    };

    logSessionEvent({
      type: isTimeout ? 'timeout' : 'logout',
      sessionId: session.sessionId,
      data: { 
        duration: Date.now() - session.startTime,
        activities: session.activityCount
      }
    });

    setSession(endedSession);

    if (isTimeout) {
      onSessionTimeout?.(endedSession);
    } else if (localConfig.secureLogout) {
      onSecureLogout?.();
    }
  }, [session, localConfig.multiTabSync, localConfig.sessionStorageKey, localConfig.secureLogout, onSessionTimeout, onSecureLogout]);

  /**
   * Pause session
   */
  const pauseSession = useCallback(() => {
    if (!session || !session.isActive) return;

    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (warningTimeoutRef.current) clearTimeout(warningTimeoutRef.current);

    setSession(prev => prev ? { ...prev, isIdle: true } : prev);
  }, [session]);

  /**
   * Resume session
   */
  const resumeSession = useCallback(() => {
    if (!session) return;

    const now = Date.now();
    const updatedSession = {
      ...session,
      isIdle: false,
      lastActivity: now
    };

    setSession(updatedSession);
    scheduleTimeout(updatedSession);
  }, [session, scheduleTimeout]);

  /**
   * Start heartbeat
   */
  const startHeartbeat = useCallback(() => {
    const heartbeat = () => {
      if (session && session.isActive) {
        recordActivity({ type: 'heartbeat' });
        
        heartbeatRef.current = setTimeout(heartbeat, localConfig.heartbeatInterval);
      }
    };

    heartbeatRef.current = setTimeout(heartbeat, localConfig.heartbeatInterval);
  }, [session, localConfig.heartbeatInterval, recordActivity]);

  /**
   * Update session time remaining
   */
  useEffect(() => {
    if (!session || !session.isActive) return;

    const interval = setInterval(() => {
      const now = Date.now();
      const remaining = Math.max(0, session.expiresAt - now);
      
      setSession(prev => prev ? {
        ...prev,
        timeRemaining: remaining,
        isIdle: (now - prev.lastActivity) > localConfig.maxIdleTime
      } : prev);

      if (remaining === 0) {
        endSession(true);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [session, localConfig.maxIdleTime, endSession]);

  /**
   * Auto-start session
   */
  useEffect(() => {
    if (autoStart && !session) {
      startSession();
    }
  }, [autoStart, session, startSession]);

  /**
   * Multi-tab synchronization
   */
  useEffect(() => {
    if (!localConfig.multiTabSync) return;

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === localConfig.sessionStorageKey) {
        if (e.newValue === null) {
          // Session ended in another tab
          endSession();
        } else {
          // Session updated in another tab
          const sessionData = JSON.parse(e.newValue);
          if (session && session.sessionId !== sessionData.sessionId) {
            // New session started in another tab
            endSession();
          }
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [localConfig.multiTabSync, localConfig.sessionStorageKey, session, endSession]);

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      if (warningTimeoutRef.current) clearTimeout(warningTimeoutRef.current);
      if (heartbeatRef.current) clearTimeout(heartbeatRef.current);
      activityListenersRef.current.forEach(cleanup => cleanup());
    };
  }, []);

  const contextValue: SessionContextValue = {
    session,
    startSession,
    extendSession,
    endSession: () => endSession(false),
    pauseSession,
    resumeSession,
    isSessionActive: () => session?.isActive || false,
    getTimeRemaining: () => session?.timeRemaining || 0
  };

  const formatTime = (ms: number): string => {
    const totalSeconds = Math.ceil(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  const getTimeColor = (timeRemaining: number): string => {
    if (timeRemaining < localConfig.warningThreshold / 2) return 'text-red-600';
    if (timeRemaining < localConfig.warningThreshold) return 'text-orange-600';
    return 'text-green-600';
  };

  return (
    <SessionContext.Provider value={contextValue}>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-blue-600" />
            Session Management
            {session?.isActive && (
              <Badge variant={session.isIdle ? 'secondary' : 'default'}>
                {session.isIdle ? 'Idle' : 'Active'}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Session Status */}
          {session && session.isActive ? (
            <div className="space-y-3">
              {/* Time Remaining */}
              <div className="text-center">
                <div className={`text-3xl font-mono font-bold ${getTimeColor(session.timeRemaining)}`}>
                  {formatTime(session.timeRemaining)}
                </div>
                <div className="text-sm text-gray-500">Time Remaining</div>
                <Progress 
                  value={(session.timeRemaining / localConfig.defaultTimeout) * 100} 
                  className="mt-2"
                />
              </div>

              {/* Session Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <Label className="text-gray-500">Activities</Label>
                  <div className="font-medium">{session.activityCount}</div>
                </div>
                <div>
                  <Label className="text-gray-500">Warnings</Label>
                  <div className="font-medium">{session.warnings}</div>
                </div>
                <div>
                  <Label className="text-gray-500">Last Activity</Label>
                  <div className="font-medium">
                    {formatTime(Date.now() - session.lastActivity)} ago
                  </div>
                </div>
                <div>
                  <Label className="text-gray-500">Session ID</Label>
                  <div className="font-mono text-xs">{session.sessionId.slice(-8)}</div>
                </div>
              </div>

              {/* Warning Alert */}
              {session.timeRemaining < localConfig.warningThreshold && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Your session will expire in {formatTime(session.timeRemaining)}. 
                    Click Extend to continue.
                  </AlertDescription>
                </Alert>
              )}

              {/* Control Buttons */}
              <div className="grid grid-cols-2 gap-2">
                <Button
                  onClick={() => extendSession()}
                  variant="outline"
                  size="sm"
                >
                  <Clock className="h-4 w-4 mr-2" />
                  Extend
                </Button>
                <Button
                  onClick={() => endSession(false)}
                  variant="outline"
                  size="sm"
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </Button>
                <Button
                  onClick={session.isIdle ? resumeSession : pauseSession}
                  variant="outline"
                  size="sm"
                >
                  {session.isIdle ? (
                    <Play className="h-4 w-4 mr-2" />
                  ) : (
                    <Pause className="h-4 w-4 mr-2" />
                  )}
                  {session.isIdle ? 'Resume' : 'Pause'}
                </Button>
                <Button
                  onClick={() => setIsConfigVisible(!isConfigVisible)}
                  variant="ghost"
                  size="sm"
                >
                  <Settings className="h-4 w-4 mr-2" />
                  Config
                </Button>
              </div>
            </div>
          ) : (
            <div className="text-center space-y-4">
              <div className="p-4 bg-gray-100 rounded-full w-fit mx-auto">
                <Shield className="h-8 w-8 text-gray-600" />
              </div>
              <div>
                <h3 className="font-medium">No Active Session</h3>
                <p className="text-sm text-gray-600">
                  Start a new session to begin secure authentication
                </p>
              </div>
              <Button onClick={startSession} className="w-full">
                <Activity className="h-4 w-4 mr-2" />
                Start Session
              </Button>
            </div>
          )}

          {/* Configuration Panel */}
          {isConfigVisible && (
            <div className="space-y-4 border-t pt-4">
              <h4 className="font-medium">Session Configuration</h4>
              
              <div className="space-y-3">
                <div>
                  <Label>Session Timeout (minutes)</Label>
                  <Slider
                    value={[localConfig.defaultTimeout / 60000]}
                    onValueChange={([value]) => setLocalConfig(prev => ({
                      ...prev,
                      defaultTimeout: value * 60000
                    }))}
                    min={5}
                    max={120}
                    step={5}
                    className="mt-2"
                  />
                  <div className="text-sm text-gray-500 mt-1">
                    {localConfig.defaultTimeout / 60000} minutes
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="extend-on-activity"
                    checked={localConfig.extendOnActivity}
                    onCheckedChange={(checked) => setLocalConfig(prev => ({
                      ...prev,
                      extendOnActivity: checked
                    }))}
                  />
                  <Label htmlFor="extend-on-activity">Extend on activity</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="track-activity"
                    checked={localConfig.trackActivity}
                    onCheckedChange={(checked) => setLocalConfig(prev => ({
                      ...prev,
                      trackActivity: checked
                    }))}
                  />
                  <Label htmlFor="track-activity">Track user activity</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="multi-tab-sync"
                    checked={localConfig.multiTabSync}
                    onCheckedChange={(checked) => setLocalConfig(prev => ({
                      ...prev,
                      multiTabSync: checked
                    }))}
                  />
                  <Label htmlFor="multi-tab-sync">Multi-tab synchronization</Label>
                </div>
              </div>
            </div>
          )}

          {/* Recent Activity */}
          {localConfig.trackActivity && recentActivity.length > 0 && (
            <div className="space-y-2">
              <h4 className="font-medium text-sm">Recent Activity</h4>
              <div className="max-h-32 overflow-y-auto bg-gray-50 p-2 rounded text-xs">
                {recentActivity.slice(0, 10).map((activity, index) => (
                  <div key={index} className="flex justify-between items-center py-1">
                    <span className="capitalize">{activity.type}</span>
                    <span className="text-gray-500">
                      {formatTime(Date.now() - activity.timestamp)} ago
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Information */}
          <div className="text-xs text-gray-500 space-y-1">
            <p>• Session automatically expires after configured timeout</p>
            <p>• Activity tracking enhances security monitoring</p>
            <p>• Multi-tab synchronization prevents session conflicts</p>
            <p>• All session events are logged for audit purposes</p>
          </div>
        </CardContent>
      </Card>
      {children}
    </SessionContext.Provider>
  );
}

export default SessionManagement;