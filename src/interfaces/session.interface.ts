export interface Session {
  id: string;
  userId: string;
  token: string;
  refreshToken: string;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  isValid: boolean;
  issuedAt: Date;
  expiresAt: Date;
  lastActivityAt: Date;
  metadata?: Record<string, unknown>;
}

export interface CreateSessionRequest {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  metadata?: Record<string, unknown>;
}

export interface SessionStore {
  create(session: Session): Promise<Session>;
  findById(sessionId: string): Promise<Session | null>;
  findByToken(token: string): Promise<Session | null>;
  findByRefreshToken(refreshToken: string): Promise<Session | null>;
  findByUserId(userId: string): Promise<Session[]>;
  invalidate(sessionId: string): Promise<void>;
  invalidateAllForUser(userId: string): Promise<void>;
  updateActivity(sessionId: string): Promise<void>;
  deleteExpired(): Promise<number>;
}
