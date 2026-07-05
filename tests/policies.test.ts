import { DefaultPolicyService } from '../src/policies';
import { PermissionAction } from '../src/interfaces';

describe('DefaultPolicyService', () => {
  let policyService: DefaultPolicyService;

  beforeEach(async () => {
    policyService = new DefaultPolicyService();

    await policyService.createPolicy({
      name: 'Deny Premium Content',
      description: 'Deny access to premium content for free users',
      rules: [
        {
          id: 'rule-2',
          name: 'premium-deny',
          effect: 'deny',
          resources: ['lesson:premium'],
          actions: [PermissionAction.READ],
          conditions: [
            { field: 'tier', operator: 'eq', value: 'free' },
          ],
          priority: 1,
        },
      ],
      isEnabled: true,
      priority: 1,
    });

    await policyService.createPolicy({
      name: 'Allow Lesson Read',
      description: 'Allow reading lessons',
      rules: [
        {
          id: 'rule-1',
          name: 'lesson-read',
          effect: 'allow',
          resources: ['lesson:*'],
          actions: [PermissionAction.READ],
          priority: 2,
        },
      ],
      isEnabled: true,
      priority: 2,
    });
  });

  it('should allow access to matching resource', async () => {
    const result = await policyService.evaluate({
      userId: 'user-1',
      resource: 'lesson:math',
      action: PermissionAction.READ,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedRule).toBeDefined();
  });

  it('should deny access when no policy matches', async () => {
    const result = await policyService.evaluate({
      userId: 'user-1',
      resource: 'lesson:math',
      action: PermissionAction.DELETE,
    });
    expect(result.allowed).toBe(false);
  });

  it('should deny access based on conditions', async () => {
    const result = await policyService.evaluate({
      userId: 'user-1',
      resource: 'lesson:premium',
      action: PermissionAction.READ,
      context: { tier: 'free' },
    });
    expect(result.allowed).toBe(false);
  });

  it('should allow access when condition does not match', async () => {
    const result = await policyService.evaluate({
      userId: 'user-1',
      resource: 'lesson:premium',
      action: PermissionAction.READ,
      context: { tier: 'premium' },
    });
    expect(result.allowed).toBe(true);
  });

  it('should get all policies sorted by priority', async () => {
    const policies = await policyService.getAllPolicies();
    expect(policies).toHaveLength(2);
    expect(policies[0].priority).toBeLessThanOrEqual(policies[1].priority);
  });
});
