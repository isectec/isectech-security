/**
 * Audit Logging Middleware
 * Tracks and logs API requests for security and compliance
 */

import { NextRequest } from 'next/server';

export interface AuditLog {
  timestamp: Date;
  userId?: string;
  method: string;
  path: string;
  ip?: string;
  userAgent?: string;
  statusCode?: number;
  duration?: number;
  metadata?: Record<string, any>;
}

export class AuditLogger {
  private static logs: AuditLog[] = [];

  static log(entry: Partial<AuditLog>): void {
    const log: AuditLog = {
      timestamp: new Date(),
      method: entry.method || 'UNKNOWN',
      path: entry.path || '/',
      ...entry
    };
    
    this.logs.push(log);
    
    // In production, this would send to a logging service
    if (process.env.NODE_ENV === 'production') {
      console.log('[AUDIT]', JSON.stringify(log));
    }
  }

  static async middleware(
    request: NextRequest,
    handler: () => Promise<Response>
  ): Promise<Response> {
    const startTime = Date.now();
    
    const auditEntry: Partial<AuditLog> = {
      method: request.method,
      path: request.nextUrl.pathname,
      ip: request.ip || request.headers.get('x-forwarded-for') || undefined,
      userAgent: request.headers.get('user-agent') || undefined,
    };

    try {
      const response = await handler();
      
      auditEntry.statusCode = response.status;
      auditEntry.duration = Date.now() - startTime;
      
      this.log(auditEntry);
      
      return response;
    } catch (error) {
      auditEntry.statusCode = 500;
      auditEntry.duration = Date.now() - startTime;
      auditEntry.metadata = { error: error instanceof Error ? error.message : 'Unknown error' };
      
      this.log(auditEntry);
      
      throw error;
    }
  }

  static getLogs(): AuditLog[] {
    return [...this.logs];
  }

  static clearLogs(): void {
    this.logs = [];
  }
}

export const auditLog = AuditLogger.log.bind(AuditLogger);
export const auditMiddleware = AuditLogger.middleware.bind(AuditLogger);