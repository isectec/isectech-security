/**
 * Authentication Store for iSECTECH Protect
 * Production-grade state management for authentication and authorization
 */

import { create } from 'zustand';
import { createJSONStorage, persist, subscribeWithSelector } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { 
  AuthState, 
  User, 
  Tenant, 
  TokenPair, 
  SessionInfo, 
  LoginCredentials,
  MFACredentials,
  LoginResponse,
  AuthError,
  SecurityClearance,
  UserRole
} from '@/types';
import { authConfig } from '@/config/app';

interface AuthStore extends AuthState {
  // Actions
  login: (credentials: LoginCredentials) => Promise<LoginResponse>;
  loginWithMFA: (credentials: MFACredentials) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  refreshTokens: () => Promise<boolean>;
  setUser: (user: User | null) => void;
  setTenant: (tenant: Tenant | null) => void;
  setTokens: (tokens: TokenPair | null) => void;
  setSession: (session: SessionInfo | null) => void;
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
  updateLastActivity: () => void;
  checkPermission: (permission: string, resource?: string) => boolean;
  checkClearance: (requiredClearance: SecurityClearance) => boolean;
  checkRole: (requiredRole: UserRole | UserRole[]) => boolean;
  switchTenant: (tenantId: string) => Promise<boolean>;
  clearAuth: () => void;
  
  // Session management
  startSessionTimer: () => void;
  stopSessionTimer: () => void;
  isSessionExpired: () => boolean;
  getTimeToExpiry: () => number;
  
  // Security utilities
  validateSecurityContext: () => boolean;
  getSecurityHeaders: () => Record<string, string>;
  auditLogin: (success: boolean, error?: string) => void;
}

// Session timer reference
let sessionTimer: NodeJS.Timeout | null = null;
let activityTimer: NodeJS.Timeout | null = null;

// API client instance (to be injected)
let apiClient: any = null;

export const setApiClient = (client: any) => {
  apiClient = client;
};

// Initial state
const initialState: AuthState = {
  isAuthenticated: false,
  isLoading: false,
  user: null,
  tenant: null,
  tokens: null,
  session: null,
  permissions: [],
  securityClearance: 'UNCLASSIFIED',
  lastActivity: null,
  error: null,
};

export const useAuthStore = create<AuthStore>()(
  subscribeWithSelector(
    persist(
      immer((set, get) => ({
        ...initialState,

        // Authentication actions
        login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            if (!apiClient) {
              throw new Error('API client not initialized');
            }

            const response = await apiClient.post('/auth/login', credentials);
            const result: LoginResponse = response.data;

            if (result.success) {
              if (result.requiresMFA) {
                set((state) => {
                  state.isLoading = false;
                });
                return result;
              }

              // Set authentication data
              set((state) => {
                state.isAuthenticated = true;
                state.user = result.user || null;
                state.tenant = result.tenant || null;
                state.tokens = result.tokens || null;
                state.permissions = result.permissions || [];
                state.securityClearance = result.user?.securityClearance || 'UNCLASSIFIED';
                state.lastActivity = new Date();
                state.isLoading = false;
                state.error = null;
              });

              // Start session timer
              get().startSessionTimer();
              
              // Audit successful login
              get().auditLogin(true);
            } else {
              set((state) => {
                state.error = result.message || 'Login failed';
                state.isLoading = false;
              });
              
              // Audit failed login
              get().auditLogin(false, result.message);
            }

            return result;
          } catch (error: any) {
            const errorMessage = error.response?.data?.message || error.message || 'Login failed';
            
            set((state) => {
              state.error = errorMessage;
              state.isLoading = false;
            });

            // Audit failed login
            get().auditLogin(false, errorMessage);

            return {
              success: false,
              requiresMFA: false,
              message: errorMessage,
            };
          }
        },

        loginWithMFA: async (credentials: MFACredentials): Promise<LoginResponse> => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            if (!apiClient) {
              throw new Error('API client not initialized');
            }

            const response = await apiClient.post('/auth/mfa-verify', credentials);
            const result: LoginResponse = response.data;

            if (result.success && result.tokens) {
              set((state) => {
                state.isAuthenticated = true;
                state.user = result.user || null;
                state.tenant = result.tenant || null;
                state.tokens = result.tokens || null;
                state.permissions = result.permissions || [];
                state.securityClearance = result.user?.securityClearance || 'UNCLASSIFIED';
                state.lastActivity = new Date();
                state.isLoading = false;
                state.error = null;
              });

              // Start session timer
              get().startSessionTimer();
              
              // Audit successful MFA login
              get().auditLogin(true);
            } else {
              set((state) => {
                state.error = result.message || 'MFA verification failed';
                state.isLoading = false;
              });
              
              // Audit failed MFA
              get().auditLogin(false, result.message);
            }

            return result;
          } catch (error: any) {
            const errorMessage = error.response?.data?.message || error.message || 'MFA verification failed';
            
            set((state) => {
              state.error = errorMessage;
              state.isLoading = false;
            });

            // Audit failed MFA
            get().auditLogin(false, errorMessage);

            return {
              success: false,
              requiresMFA: false,
              message: errorMessage,
            };
          }
        },

        logout: async (): Promise<void> => {
          try {
            if (apiClient && get().tokens) {
              await apiClient.post('/auth/logout');
            }
          } catch (error) {
            console.warn('Logout API call failed:', error);
          } finally {
            get().clearAuth();
          }
        },

        refreshTokens: async (): Promise<boolean> => {
          const { tokens } = get();
          
          if (!tokens?.refreshToken || !apiClient) {
            return false;
          }

          try {
            const response = await apiClient.post('/auth/refresh', {
              refreshToken: tokens.refreshToken,
            });

            const newTokens: TokenPair = response.data.tokens;

            set((state) => {
              state.tokens = newTokens;
              state.lastActivity = new Date();
              state.error = null;
            });

            return true;
          } catch (error) {
            console.error('Token refresh failed:', error);
            get().clearAuth();
            return false;
          }
        },

        // State setters
        setUser: (user: User | null) => {
          set((state) => {
            state.user = user;
            if (user) {
              state.securityClearance = user.securityClearance;
            }
          });
        },

        setTenant: (tenant: Tenant | null) => {
          set((state) => {
            state.tenant = tenant;
          });
        },

        setTokens: (tokens: TokenPair | null) => {
          set((state) => {
            state.tokens = tokens;
          });
        },

        setSession: (session: SessionInfo | null) => {
          set((state) => {
            state.session = session;
          });
        },

        setError: (error: string | null) => {
          set((state) => {
            state.error = error;
          });
        },

        setLoading: (loading: boolean) => {
          set((state) => {
            state.isLoading = loading;
          });
        },

        updateLastActivity: () => {
          set((state) => {
            state.lastActivity = new Date();
          });
        },

        // Permission and authorization checks
        checkPermission: (permission: string, resource?: string): boolean => {
          const { permissions, user } = get();
          
          if (!user || !permissions.length) {
            return false;
          }

          // Super admin has all permissions
          if (user.role === 'SUPER_ADMIN') {
            return true;
          }

          // Check for wildcard permission
          if (permissions.includes('*')) {
            return true;
          }

          // Check exact permission
          if (permissions.includes(permission)) {
            return true;
          }

          // Check resource-specific permission
          if (resource && permissions.includes(`${permission}:${resource}`)) {
            return true;
          }

          return false;
        },

        checkClearance: (requiredClearance: SecurityClearance): boolean => {
          const { securityClearance } = get();
          
          const clearanceLevels = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
          const userLevel = clearanceLevels.indexOf(securityClearance);
          const requiredLevel = clearanceLevels.indexOf(requiredClearance);
          
          return userLevel >= requiredLevel;
        },

        checkRole: (requiredRole: UserRole | UserRole[]): boolean => {
          const { user } = get();
          
          if (!user) {
            return false;
          }

          // Super admin has access to everything
          if (user.role === 'SUPER_ADMIN') {
            return true;
          }

          const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
          return requiredRoles.includes(user.role);
        },

        switchTenant: async (tenantId: string): Promise<boolean> => {
          try {
            if (!apiClient) {
              return false;
            }

            const response = await apiClient.post('/auth/switch-tenant', { tenantId });
            const result = response.data;

            if (result.success) {
              set((state) => {
                state.tenant = result.tenant;
                state.permissions = result.permissions || [];
                state.lastActivity = new Date();
              });
              return true;
            }

            return false;
          } catch (error) {
            console.error('Tenant switch failed:', error);
            return false;
          }
        },

        clearAuth: () => {
          // Stop timers
          get().stopSessionTimer();
          
          // Clear state
          set((state) => {
            Object.assign(state, initialState);
          });
        },

        // Session management
        startSessionTimer: () => {
          get().stopSessionTimer();

          sessionTimer = setInterval(() => {
            const { isSessionExpired, logout } = get();
            
            if (isSessionExpired()) {
              logout();
            }
          }, 60000); // Check every minute

          // Activity timer for auto-refresh
          activityTimer = setInterval(() => {
            const { lastActivity, refreshTokens } = get();
            const now = new Date();
            const timeSinceActivity = now.getTime() - (lastActivity?.getTime() || 0);
            
            // Refresh tokens if active and close to expiry
            if (timeSinceActivity < authConfig.sessionTimeout * 1000 * 0.5) {
              refreshTokens();
            }
          }, 5 * 60 * 1000); // Check every 5 minutes
        },

        stopSessionTimer: () => {
          if (sessionTimer) {
            clearInterval(sessionTimer);
            sessionTimer = null;
          }
          if (activityTimer) {
            clearInterval(activityTimer);
            activityTimer = null;
          }
        },

        isSessionExpired: (): boolean => {
          const { tokens, lastActivity } = get();
          
          if (!tokens || !lastActivity) {
            return true;
          }

          const now = new Date();
          const sessionAge = now.getTime() - lastActivity.getTime();
          const maxSessionAge = authConfig.sessionTimeout * 1000;
          
          return sessionAge > maxSessionAge || now > tokens.expiresAt;
        },

        getTimeToExpiry: (): number => {
          const { tokens, lastActivity } = get();
          
          if (!tokens || !lastActivity) {
            return 0;
          }

          const now = new Date();
          const sessionExpiry = lastActivity.getTime() + (authConfig.sessionTimeout * 1000);
          const tokenExpiry = tokens.expiresAt.getTime();
          const earliestExpiry = Math.min(sessionExpiry, tokenExpiry);
          
          return Math.max(0, earliestExpiry - now.getTime());
        },

        // Security utilities
        validateSecurityContext: (): boolean => {
          const { isAuthenticated, user, tenant, tokens } = get();
          
          return !!(
            isAuthenticated &&
            user &&
            tenant &&
            tokens &&
            !get().isSessionExpired()
          );
        },

        getSecurityHeaders: (): Record<string, string> => {
          const { tokens, tenant, user } = get();
          
          const headers: Record<string, string> = {};
          
          if (tokens?.accessToken) {
            headers.Authorization = `Bearer ${tokens.accessToken}`;
          }
          
          if (tenant?.id) {
            headers['X-Tenant-ID'] = tenant.id;
          }
          
          if (user?.id) {
            headers['X-User-ID'] = user.id;
          }
          
          return headers;
        },

        auditLogin: (success: boolean, error?: string) => {
          if (typeof window !== 'undefined') {
            const event = {
              type: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
              timestamp: new Date().toISOString(),
              userAgent: navigator.userAgent,
              error,
            };
            
            // Store in local storage for later transmission
            const auditEvents = JSON.parse(localStorage.getItem('audit_events') || '[]');
            auditEvents.push(event);
            
            // Keep only last 100 events
            if (auditEvents.length > 100) {
              auditEvents.splice(0, auditEvents.length - 100);
            }
            
            localStorage.setItem('audit_events', JSON.stringify(auditEvents));
          }
        },
      })),
      {
        name: authConfig.tokenKey,
        storage: createJSONStorage(() => localStorage),
        partialize: (state) => ({
          isAuthenticated: state.isAuthenticated,
          user: state.user,
          tenant: state.tenant,
          tokens: state.tokens,
          session: state.session,
          permissions: state.permissions,
          securityClearance: state.securityClearance,
          lastActivity: state.lastActivity,
        }),
        version: 1,
        migrate: (persistedState: any, version: number) => {
          // Handle migration from older versions
          if (version === 0) {
            // Clear old state format
            return initialState;
          }
          return persistedState;
        },
      }
    )
  )
);

// Subscribe to authentication state changes
useAuthStore.subscribe(
  (state) => state.isAuthenticated,
  (isAuthenticated, previousIsAuthenticated) => {
    if (isAuthenticated && !previousIsAuthenticated) {
      // User just logged in
      console.info('User authenticated');
    } else if (!isAuthenticated && previousIsAuthenticated) {
      // User just logged out
      console.info('User logged out');
    }
  }
);

// Activity tracking
if (typeof window !== 'undefined') {
  const trackActivity = () => {
    const { isAuthenticated, updateLastActivity } = useAuthStore.getState();
    if (isAuthenticated) {
      updateLastActivity();
    }
  };

  // Track user activity
  ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, trackActivity, { passive: true });
  });
}

export default useAuthStore;