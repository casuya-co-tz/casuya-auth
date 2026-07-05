import { LocalProvider } from '../../src/providers';

describe('LocalProvider', () => {
  let provider: LocalProvider;

  beforeEach(() => {
    provider = new LocalProvider({
      id: 'local',
      name: 'Local',
      type: 'local',
      enabled: true,
      passwordPolicy: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: false,
      },
    });
  });

  it('should validate password policy', () => {
    const result = provider.validatePasswordAgainstPolicy('Weak1');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('should accept strong password', () => {
    const result = provider.validatePasswordAgainstPolicy('StrongPass1');
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should validate credentials', async () => {
    const hash = await provider.hashPassword('password123');
    const valid = await provider.validateCredentials({ password: 'password123', passwordHash: hash });
    expect(valid).toBe(true);
  });

  it('should reject invalid credentials', async () => {
    const hash = await provider.hashPassword('password123');
    const valid = await provider.validateCredentials({ password: 'wrong', passwordHash: hash });
    expect(valid).toBe(false);
  });

  it('should authenticate with email and password', async () => {
    const result = await provider.authenticate({
      credentials: { email: 'test@test.com', password: 'password123' },
    });
    expect(result.success).toBe(true);
  });

  it('should fail authentication without credentials', async () => {
    const result = await provider.authenticate({ credentials: {} });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});
