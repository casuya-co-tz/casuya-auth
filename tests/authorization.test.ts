import { DefaultAuthorizationService } from '../src/authorization';
import { DefaultPermissionService } from '../src/permissions';
import { PermissionAction } from '../src/interfaces';

class MockPermissionStore {
  private perms: any[] = [];
  create(p: any) { this.perms.push(p); return Promise.resolve(p); }
  findById(id: string) { return Promise.resolve(this.perms.find(p => p.id === id) ?? null); }
  findByName(n: string) { return Promise.resolve(this.perms.find(p => p.name === n) ?? null); }
  findAll() { return Promise.resolve(this.perms); }
  findByResource(r: string) { return Promise.resolve(this.perms.filter(p => p.resource === r)); }
  delete(_id: string) { return Promise.resolve(); }
  exists(n: string) { return Promise.resolve(this.perms.some(p => p.name === n)); }
}

class MockUserRoleStore {
  private assignments: Map<string, string[]> = new Map();
  private permAssignments: Map<string, string[]> = new Map();

  getUserRoles(uid: string) { return Promise.resolve(this.assignments.get(uid) ?? []); }
  getUserPermissions(uid: string) { return Promise.resolve(this.permAssignments.get(uid) ?? []); }
  assignRole(uid: string, role: string) {
    const roles = this.assignments.get(uid) ?? [];
    roles.push(role);
    this.assignments.set(uid, roles);
    return Promise.resolve();
  }
  revokeRole(uid: string, role: string) {
    const roles = this.assignments.get(uid) ?? [];
    this.assignments.set(uid, roles.filter(r => r !== role));
    return Promise.resolve();
  }
  userHasRole(uid: string, role: string) {
    return Promise.resolve((this.assignments.get(uid) ?? []).includes(role));
  }
  grantPermission(uid: string, perm: string) {
    const perms = this.permAssignments.get(uid) ?? [];
    perms.push(perm);
    this.permAssignments.set(uid, perms);
    return Promise.resolve();
  }
  revokePermission(uid: string, perm: string) {
    const perms = this.permAssignments.get(uid) ?? [];
    this.permAssignments.set(uid, perms.filter(p => p !== perm));
    return Promise.resolve();
  }
}

describe('DefaultAuthorizationService', () => {
  let authz: DefaultAuthorizationService;
  let permService: DefaultPermissionService;
  let userRoleStore: MockUserRoleStore;

  beforeEach(async () => {
    const permissionStore = new MockPermissionStore();
    userRoleStore = new MockUserRoleStore();

    permService = new DefaultPermissionService(permissionStore as any, userRoleStore as any);
    authz = new DefaultAuthorizationService(userRoleStore as any);

    await permService.grantPermission('user-1', 'lessons:read');
  });

  it('should allow user with permission', async () => {
    const result = await authz.checkPermission({
      userId: 'user-1',
      resource: 'lessons',
      action: PermissionAction.READ,
    });
    expect(result.allowed).toBe(true);
  });

  it('should deny user without permission', async () => {
    const result = await authz.checkPermission({
      userId: 'user-2',
      resource: 'lessons',
      action: PermissionAction.READ,
    });
    expect(result.allowed).toBe(false);
  });

  it('should allow user with manage permission', async () => {
    await permService.grantPermission('user-1', 'lessons:manage');
    const result = await authz.checkPermission({
      userId: 'user-1',
      resource: 'lessons',
      action: PermissionAction.DELETE,
    });
    expect(result.allowed).toBe(true);
  });

  it('should assign and check roles', async () => {
    await authz.assignRole('user-1', 'admin');
    const hasRole = await authz.hasRole('user-1', 'admin');
    expect(hasRole).toBe(true);
  });

  it('should check any role', async () => {
    await authz.assignRole('user-1', 'editor');
    const hasAny = await authz.hasAnyRole('user-1', ['admin', 'editor']);
    expect(hasAny).toBe(true);
  });

  it('should check all roles', async () => {
    await authz.assignRole('user-1', 'admin');
    await authz.assignRole('user-1', 'editor');
    const hasAll = await authz.hasAllRoles('user-1', ['admin', 'editor']);
    expect(hasAll).toBe(true);
  });
});
