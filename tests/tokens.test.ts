import { JwtTokenService } from '../src/tokens';

describe('JwtTokenService', () => {
  const config = {
    accessTokenSecret: 'test-access-secret-32-chars-minimum!',
    refreshTokenSecret: 'test-refresh-secret-32-chars-min!',
    accessTokenExpiration: '1h',
    refreshTokenExpiration: '7d',
    issuer: 'casuya-test',
  };

  let tokenService: JwtTokenService;

  beforeEach(() => {
    tokenService = new JwtTokenService(config);
  });

  it('should generate token pair', async () => {
    const pair = await tokenService.generateTokenPair({ sub: 'user-1' });
    expect(pair.accessToken).toBeTruthy();
    expect(pair.refreshToken).toBeTruthy();
    expect(pair.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(pair.refreshTokenExpiresAt).toBeInstanceOf(Date);
  });

  it('should verify valid access token', async () => {
    const pair = await tokenService.generateTokenPair({ sub: 'user-1' });
    const result = await tokenService.verifyAccessToken(pair.accessToken);
    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('user-1');
  });

  it('should reject invalid access token', async () => {
    const result = await tokenService.verifyAccessToken('invalid-token');
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should reject revoked token', async () => {
    const pair = await tokenService.generateTokenPair({ sub: 'user-1' });
    const payload = tokenService.decodeToken(pair.accessToken);
    if (payload?.jti) {
      await tokenService.revokeToken(payload.jti);
    }
    const result = await tokenService.verifyAccessToken(pair.accessToken);
    expect(result.valid).toBe(false);
  });

  it('should decode token without verification', async () => {
    const pair = await tokenService.generateTokenPair({ sub: 'user-1' });
    const payload = tokenService.decodeToken(pair.accessToken);
    expect(payload?.sub).toBe('user-1');
  });
});
