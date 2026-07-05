import { UserProfile, TokenPair, Session } from '../interfaces';

export interface LoginRequest {
  provider: string;
  credentials: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  metadata?: Record<string, unknown>;
}

export interface RegisterRequest {
  provider: string;
  credentials: Record<string, unknown>;
  profile: {
    email: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
    locale?: string;
  };
  metadata?: Record<string, unknown>;
}

export interface LoginResponse {
  success: boolean;
  user?: UserProfile;
  tokens?: TokenPair;
  session?: Session;
  error?: string;
}

export interface RegisterResponse {
  success: boolean;
  user?: UserProfile;
  error?: string;
}

export interface AuthenticationService {
  login(request: LoginRequest): Promise<LoginResponse>;
  register(request: RegisterRequest): Promise<RegisterResponse>;
  logout(sessionId: string, userId: string): Promise<void>;
  logoutAllSessions(userId: string): Promise<void>;
  verifyEmail(token: string): Promise<boolean>;
  refreshSession(refreshToken: string): Promise<LoginResponse>;
  getSession(sessionId: string): Promise<Session | null>;
  getUserSessions(userId: string): Promise<Session[]>;
}

export interface ProviderRegistry {
  registerProvider(provider: import('../providers').AuthProvider): void;
  getProvider(providerId: string): import('../providers').AuthProvider;
  getAvailableProviders(): string[];
  removeProvider(providerId: string): void;
}
