import { v4 as uuid } from 'uuid';
import { SessionService } from './session.service.interface';
import { Session, CreateSessionRequest, SessionStore } from '../interfaces';

export class DefaultSessionService implements SessionService {
  private readonly sessionStore: SessionStore;

  constructor(sessionStore: SessionStore) {
    this.sessionStore = sessionStore;
  }

  async createSession(request: CreateSessionRequest): Promise<Session> {
    const session: Session = {
      id: uuid(),
      userId: request.userId,
      token: uuid(),
      refreshToken: uuid(),
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
      deviceId: request.deviceId,
      isValid: true,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      lastActivityAt: new Date(),
      metadata: request.metadata,
    };
    return this.sessionStore.create(session);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return this.sessionStore.findById(sessionId);
  }

  async getSessionByToken(token: string): Promise<Session | null> {
    return this.sessionStore.findByToken(token);
  }

  async getUserSessions(userId: string): Promise<Session[]> {
    return this.sessionStore.findByUserId(userId);
  }

  async invalidateSession(sessionId: string): Promise<void> {
    return this.sessionStore.invalidate(sessionId);
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    return this.sessionStore.invalidateAllForUser(userId);
  }

  async updateActivity(sessionId: string): Promise<void> {
    return this.sessionStore.updateActivity(sessionId);
  }

  async cleanupExpiredSessions(): Promise<number> {
    return this.sessionStore.deleteExpired();
  }
}
