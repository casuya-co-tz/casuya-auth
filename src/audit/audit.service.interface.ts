export enum AuditEventType {
  LOGIN = 'login',
  LOGOUT = 'logout',
  LOGIN_FAILED = 'login_failed',
  REGISTER = 'register',
  PASSWORD_CHANGE = 'password_change',
  PASSWORD_RESET = 'password_reset',
  EMAIL_VERIFY = 'email_verify',
  MFA_ENABLE = 'mfa_enable',
  MFA_DISABLE = 'mfa_disable',
  ROLE_ASSIGN = 'role_assign',
  ROLE_REVOKE = 'role_revoke',
  PERMISSION_GRANT = 'permission_grant',
  PERMISSION_REVOKE = 'permission_revoke',
  SESSION_INVALIDATE = 'session_invalidate',
  TOKEN_REFRESH = 'token_refresh',
  ACCOUNT_LOCKED = 'account_locked',
  ACCOUNT_UNLOCKED = 'account_unlocked',
  PROFILE_UPDATE = 'profile_update',
  SSO_LOGIN = 'sso_login',
  POLICY_CHANGE = 'policy_change',
}

export interface AuditEvent {
  id: string;
  eventType: AuditEventType;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  resource?: string;
  action?: string;
  status: 'success' | 'failure' | 'pending';
  details?: Record<string, unknown>;
  error?: string;
  timestamp: Date;
  correlationId?: string;
}

export interface AuditQuery {
  userId?: string;
  eventType?: AuditEventType;
  resource?: string;
  status?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
}

export interface AuditService {
  record(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<AuditEvent>;
  query(query: AuditQuery): Promise<AuditEvent[]>;
  getById(eventId: string): Promise<AuditEvent | null>;
  getByUser(userId: string, page?: number, limit?: number): Promise<AuditEvent[]>;
  getByResource(resource: string, page?: number, limit?: number): Promise<AuditEvent[]>;
  getFailedEvents(page?: number, limit?: number): Promise<AuditEvent[]>;
  count(query: AuditQuery): Promise<number>;
  export(userId?: string, startDate?: Date, endDate?: Date): Promise<AuditEvent[]>;
  getRetentionPeriod(): Promise<number>;
}
