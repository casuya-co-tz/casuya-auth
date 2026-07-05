import { DefaultMfaService } from '../src/mfa';
import { MfaMethod } from '../src/interfaces';

describe('DefaultMfaService', () => {
  let mfaService: DefaultMfaService;

  beforeEach(() => {
    mfaService = new DefaultMfaService('CasuyaTest');
  });

  it('should setup TOTP MFA', async () => {
    const result = await mfaService.setupMfa('user-1', MfaMethod.TOTP);
    expect(result.secret).toBeTruthy();
    expect(result.qrCodeUrl).toBeTruthy();
    expect(result.backupCodes).toHaveLength(10);
    expect(result.method).toBe(MfaMethod.TOTP);
  });

  it('should verify backup code', async () => {
    const setup = await mfaService.setupMfa('user-1', MfaMethod.TOTP);
    const code = setup.backupCodes[0];
    const valid = await mfaService.verifyBackupCode('user-1', code);
    expect(valid).toBe(true);
  });

  it('should not reuse backup code', async () => {
    const setup = await mfaService.setupMfa('user-1', MfaMethod.TOTP);
    const code = setup.backupCodes[0];
    await mfaService.verifyBackupCode('user-1', code);
    const valid = await mfaService.verifyBackupCode('user-1', code);
    expect(valid).toBe(false);
  });

  it('should disable MFA', async () => {
    await mfaService.setupMfa('user-1', MfaMethod.TOTP);
    await mfaService.disableMfa('user-1');
    const enabled = await mfaService.isMfaEnabled('user-1');
    expect(enabled).toBe(false);
  });
});
