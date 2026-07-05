import { DefaultAuthenticationService } from '../src/authentication';
import { JwtTokenService } from '../src/tokens';
import { UserProfile } from '../src/interfaces';

class MockSessionStore {
  private sessions: any[] = [];
  create(s: any) { this.sessions.push(s); return Promise.resolve(s); }
  findById(id: string) { return Promise.resolve(this.sessions.find(s => s.id === id) ?? null); }
  findByToken(t: string) { return Promise.resolve(this.sessions.find(s => s.token === t) ?? null); }
  findByRefreshToken(t: string) { return Promise.resolve(this.sessions.find(s => s.refreshToken === t) ?? null); }
  findByUserId(uid: string) { return Promise.resolve(this.sessions.filter(s => s.userId === uid)); }
  invalidate(id: string) { const s = this.sessions.find(x => x.id === id); if (s) s.isValid = false; return Promise.resolve(); }
  invalidateAllForUser(uid: string) { this.sessions.filter(s => s.userId === uid).forEach(s => s.isValid = false); return Promise.resolve(); }
  updateActivity(_id: string) { return Promise.resolve(); }
  deleteExpired() { return Promise.resolve(0); }
}

class MockUserStore {
  private users: UserProfile[] = [];
  create(u: UserProfile) { this.users.push(u); return Promise.resolve(u); }
  findById(id: string) { return Promise.resolve(this.users.find(u => u.id === id) ?? null); }
  findByEmail(email: string) { return Promise.resolve(this.users.find(u => u.email === email) ?? null); }
  findByProvider(_p: string, pid: string) { return Promise.resolve(this.users.find(u => u.id === pid) ?? null); }
}

describe('DefaultAuthenticationService', () => {
  let authService: DefaultAuthenticationService;
  let mockProvider: any;

  beforeEach(() => {
    const tokenService = new JwtTokenService({
      accessTokenSecret: 'test-access-secret-min-32-chars!!',
      refreshTokenSecret: 'test-refresh-secret-min-32-chars!',
      accessTokenExpiration: '1h',
      refreshTokenExpiration: '7d',
    });

    const sessionStore = new MockSessionStore();
    const userStore = new MockUserStore();

    authService = new DefaultAuthenticationService(tokenService, sessionStore as any, userStore as any);

    mockProvider = {
      config: { id: 'local', name: 'Local', type: 'local', enabled: true },
      authenticate: jest.fn().mockResolvedValue({ success: true, userId: 'user-1', profile: { id: 'user-1', email: 'test@test.com', username: 'test', displayName: 'Test' } }),
      validateCredentials: jest.fn().mockResolvedValue(true),
      linkAccount: jest.fn(),
      unlinkAccount: jest.fn(),
      getProfile: jest.fn(),
      initialize: jest.fn(),
      healthCheck: jest.fn().mockResolvedValue(true),
    };

    authService.registerProvider(mockProvider);

    userStore.create({
      id: 'user-1',
      email: 'test@test.com',
      username: 'test',
      displayName: 'Test',
    });
  });

  it('should login successfully', async () => {
    const result = await authService.login({
      provider: 'local',
      credentials: { email: 'test@test.com', password: 'password123' },
    });
    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.tokens).toBeDefined();
    expect(result.session).toBeDefined();
  });

  it('should fail login with invalid provider', async () => {
    const result = await authService.login({
      provider: 'nonexistent',
      credentials: {},
    });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should get available providers', () => {
    const providers = authService.getAvailableProviders();
    expect(providers).toContain('local');
  });

  it('should logout and invalidate session', async () => {
    const loginResult = await authService.login({
      provider: 'local',
      credentials: { email: 'test@test.com', password: 'password123' },
    });
    expect(loginResult.session).toBeDefined();
    await authService.logout(loginResult.session!.id, 'user-1');
    const session = await authService.getSession(loginResult.session!.id);
    expect(session?.isValid).toBe(false);
  });
});
