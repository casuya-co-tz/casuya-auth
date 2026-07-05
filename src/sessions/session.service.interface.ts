import { Session, CreateSessionRequest } from '../interfaces';

export interface SessionService {
  createSession(request: CreateSessionRequest): Promise<Session>;
  getSession(sessionId: string): Promise<Session | null>;
  getSessionByToken(token: string): Promise<Session | null>;
  getUserSessions(userId: string): Promise<Session[]>;
  invalidateSession(sessionId: string): Promise<void>;
  invalidateAllUserSessions(userId: string): Promise<void>;
  updateActivity(sessionId: string): Promise<void>;
  cleanupExpiredSessions(): Promise<number>;
}
