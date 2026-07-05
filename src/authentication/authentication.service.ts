import { v4 as uuid } from 'uuid';
import { AuthenticationService, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse } from './authentication.service.interface';
import { ProviderRegistry } from './authentication.service.interface';
import { SessionStore, UserProfile } from '../interfaces';
import { TokenService } from '../tokens';
import { AuthProvider } from '../providers';

export class DefaultAuthenticationService implements AuthenticationService, ProviderRegistry {
  private readonly providers: Map<string, AuthProvider> = new Map();
  private readonly tokenService: TokenService;
  private readonly sessionStore: SessionStore;
  private readonly userStore: {
    create(user: UserProfile): Promise<UserProfile>;
    findById(id: string): Promise<UserProfile | null>;
    findByEmail(email: string): Promise<UserProfile | null>;
    findByProvider(provider: string, providerId: string): Promise<UserProfile | null>;
  };

  constructor(
    tokenService: TokenService,
    sessionStore: SessionStore,
    userStore: {
      create(user: UserProfile): Promise<UserProfile>;
      findById(id: string): Promise<UserProfile | null>;
      findByEmail(email: string): Promise<UserProfile | null>;
      findByProvider(provider: string, providerId: string): Promise<UserProfile | null>;
    },
  ) {
    this.tokenService = tokenService;
    this.sessionStore = sessionStore;
    this.userStore = userStore;
  }

  registerProvider(provider: AuthProvider): void {
    this.providers.set(provider.config.id, provider);
  }

  getProvider(providerId: string): AuthProvider {
    const provider = this.providers.get(providerId);
    if (!provider) {
      throw new Error(`Provider ${providerId} not registered`);
    }
    return provider;
  }

  getAvailableProviders(): string[] {
    return Array.from(this.providers.keys());
  }

  removeProvider(providerId: string): void {
    this.providers.delete(providerId);
  }

  async login(request: LoginRequest): Promise<LoginResponse> {
    try {
      const provider = this.getProvider(request.provider);
      const authResult = await provider.authenticate({
        credentials: request.credentials,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        metadata: request.metadata,
      });

      if (!authResult.success || !authResult.userId) {
        return { success: false, error: authResult.error ?? 'Authentication failed' };
      }

      let user = await this.userStore.findByProvider(request.provider, authResult.userId);
      if (!user) {
        user = await this.userStore.findByEmail(authResult.profile?.email ?? '');
      }

      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const tokenPair = await this.tokenService.generateTokenPair({
        sub: user.id,
        provider: request.provider,
      });

      const session = await this.sessionStore.create({
        id: uuid(),
        userId: user.id,
        token: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        deviceId: request.deviceId,
        isValid: true,
        issuedAt: new Date(),
        expiresAt: tokenPair.accessTokenExpiresAt,
        lastActivityAt: new Date(),
        metadata: request.metadata,
      });

      return {
        success: true,
        user,
        tokens: tokenPair,
        session,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      return { success: false, error: message };
    }
  }

  async register(request: RegisterRequest): Promise<RegisterResponse> {
    try {
      const provider = this.getProvider(request.provider);

      const existingUser = await this.userStore.findByEmail(request.profile.email);
      if (existingUser) {
        return { success: false, error: 'Email already registered' };
      }

      const user: UserProfile = {
        id: uuid(),
        email: request.profile.email,
        username: request.profile.username,
        displayName: request.profile.displayName,
        avatarUrl: request.profile.avatarUrl,
        locale: request.profile.locale,
        metadata: request.metadata,
      };

      const created = await this.userStore.create(user);
      await provider.linkAccount({
        userId: created.id,
        providerId: created.id,
        providerData: request.credentials,
      });

      return { success: true, user: created };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      return { success: false, error: message };
    }
  }

  async logout(sessionId: string, _userId: string): Promise<void> {
    await this.sessionStore.invalidate(sessionId);
  }

  async logoutAllSessions(userId: string): Promise<void> {
    await this.sessionStore.invalidateAllForUser(userId);
  }

  async verifyEmail(_token: string): Promise<boolean> {
    return true;
  }

  async refreshSession(refreshToken: string): Promise<LoginResponse> {
    try {
      const verification = await this.tokenService.verifyRefreshToken(refreshToken);
      if (!verification.valid || !verification.payload) {
        return { success: false, error: 'Invalid refresh token' };
      }

      const session = await this.sessionStore.findByRefreshToken(refreshToken);
      if (!session || !session.isValid) {
        return { success: false, error: 'Session not found or invalid' };
      }

      const userId = verification.payload.sub as string;
      const user = await this.userStore.findById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      await this.sessionStore.invalidate(session.id);

      const tokenPair = await this.tokenService.generateTokenPair({ sub: userId, provider: 'refresh' });

      const newSession = await this.sessionStore.create({
        id: uuid(),
        userId: user.id,
        token: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        deviceId: session.deviceId,
        isValid: true,
        issuedAt: new Date(),
        expiresAt: tokenPair.accessTokenExpiresAt,
        lastActivityAt: new Date(),
        metadata: session.metadata,
      });

      return {
        success: true,
        user,
        tokens: tokenPair,
        session: newSession,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Session refresh failed';
      return { success: false, error: message };
    }
  }

  async getSession(sessionId: string): Promise<import('../interfaces').Session | null> {
    return this.sessionStore.findById(sessionId);
  }

  async getUserSessions(userId: string): Promise<import('../interfaces').Session[]> {
    return this.sessionStore.findByUserId(userId);
  }
}
