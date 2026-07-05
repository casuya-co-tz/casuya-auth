import { DefaultPasswordService } from '../src/passwords';

describe('DefaultPasswordService', () => {
  let passwordService: DefaultPasswordService;

  beforeEach(() => {
    passwordService = new DefaultPasswordService({
      minLength: 8,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: false,
    });
  });

  it('should hash and verify password', async () => {
    const hash = await passwordService.hashPassword('TestPass123');
    expect(hash).toBeTruthy();
    expect(hash).not.toBe('TestPass123');
    const valid = await passwordService.verifyPassword('TestPass123', hash);
    expect(valid).toBe(true);
  });

  it('should reject wrong password', async () => {
    const hash = await passwordService.hashPassword('TestPass123');
    const valid = await passwordService.verifyPassword('WrongPass123', hash);
    expect(valid).toBe(false);
  });

  it('should validate strong password', () => {
    const result = passwordService.validatePasswordStrength('StrongP1');
    expect(result.valid).toBe(true);
    expect(result.score).toBeGreaterThan(0);
  });

  it('should reject weak password', () => {
    const result = passwordService.validatePasswordStrength('weak');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('should generate and verify reset token', async () => {
    const token = await passwordService.generateResetToken('user-1');
    expect(token).toBeTruthy();
    const userId = await passwordService.verifyResetToken(token);
    expect(userId).toBe('user-1');
  });

  it('should reject invalid reset token', async () => {
    const userId = await passwordService.verifyResetToken('invalid-token');
    expect(userId).toBeNull();
  });
});
