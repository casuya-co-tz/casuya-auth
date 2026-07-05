import { DefaultSsoService } from '../src/sso';
import { SsoProtocol } from '../src/sso';

describe('DefaultSsoService', () => {
  let ssoService: DefaultSsoService;

  beforeEach(async () => {
    ssoService = new DefaultSsoService();
    await ssoService.registerProvider({
      id: 'google-workspace',
      name: 'Google Workspace',
      type: SsoProtocol.OIDC,
      enabled: true,
      metadataUrl: 'https://accounts.google.com/.well-known/openid-configuration',
      entityId: 'https://casuya.example.com',
    });
  });

  it('should list enabled providers', async () => {
    const providers = await ssoService.getProviders();
    expect(providers).toHaveLength(1);
    expect(providers[0].id).toBe('google-workspace');
  });

  it('should initiate login', async () => {
    const response = await ssoService.initiateLogin({
      providerId: 'google-workspace',
    });
    expect(response.providerId).toBe('google-workspace');
    expect(response.redirectUrl).toBeTruthy();
  });

  it('should handle callback', async () => {
    const result = await ssoService.handleCallback({
      providerId: 'google-workspace',
      token: 'sso-token-123',
    });
    expect(result.success).toBe(true);
    expect(result.userId).toBeDefined();
  });

  it('should fail with unknown provider', async () => {
    const result = await ssoService.handleCallback({
      providerId: 'unknown',
      token: 'token',
    });
    expect(result.success).toBe(false);
  });

  it('should check if SSO is enabled', async () => {
    const enabled = await ssoService.isEnabled();
    expect(enabled).toBe(true);
  });

  it('should unregister provider', async () => {
    await ssoService.unregisterProvider('google-workspace');
    const providers = await ssoService.getProviders();
    expect(providers).toHaveLength(0);
  });
});
