import { DefaultAuthMiddleware } from '../src/middleware';
import { JwtTokenService } from '../src/tokens';
import { DefaultAuthorizationService } from '../src/authorization';

class MockUserRoleStore {
  getUserRoles = jest.fn().mockResolvedValue(['user']);
  getUserPermissions = jest.fn().mockResolvedValue(['lessons:read']);
  assignRole = jest.fn();
  revokeRole = jest.fn();
  userHasRole = jest.fn().mockResolvedValue(true);
}

describe('DefaultAuthMiddleware', () => {
  let middleware: DefaultAuthMiddleware;
  let tokenService: JwtTokenService;

  beforeEach(() => {
    tokenService = new JwtTokenService({
      accessTokenSecret: 'test-access-secret-32-chars-minimum!',
      refreshTokenSecret: 'test-refresh-secret-32-chars-min!',
      accessTokenExpiration: '1h',
      refreshTokenExpiration: '7d',
    });

    const authz = new DefaultAuthorizationService(
      new MockUserRoleStore() as any,
    );

    middleware = new DefaultAuthMiddleware(tokenService, authz);
  });

  it('should authenticate with valid token', async () => {
    const pair = await tokenService.generateTokenPair({ sub: 'user-1' });
    const result = await middleware.authenticate(pair.accessToken);
    expect(result).not.toBeNull();
    expect(result!.userId).toBe('user-1');
  });

  it('should return null with invalid token', async () => {
    const result = await middleware.authenticate('invalid-token');
    expect(result).toBeNull();
  });
});
