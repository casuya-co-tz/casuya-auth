import { AuthorizationService, AuthorizationCheck, AuthorizationResult } from './authorization.service.interface';
import { PermissionAction } from '../interfaces';

export interface UserRoleStore {
  getUserRoles(userId: string): Promise<string[]>;
  getUserPermissions(userId: string): Promise<string[]>;
  assignRole(userId: string, roleName: string): Promise<void>;
  revokeRole(userId: string, roleName: string): Promise<void>;
  userHasRole(userId: string, roleName: string): Promise<boolean>;
}

export class DefaultAuthorizationService implements AuthorizationService {
  private readonly userRoleStore: UserRoleStore;

  constructor(userRoleStore: UserRoleStore) {
    this.userRoleStore = userRoleStore;
  }

  async checkPermission(check: AuthorizationCheck): Promise<AuthorizationResult> {
    try {
      const userPermissions = await this.userRoleStore.getUserPermissions(check.userId);

      const requiredPermission = `${check.resource}:${check.action}`;
      const hasPermission = userPermissions.includes(requiredPermission);

      if (hasPermission) {
        return { allowed: true, context: check.context };
      }

      const wildcardPermission = `${check.resource}:${PermissionAction.MANAGE}`;
      const hasWildcard = userPermissions.includes(wildcardPermission);

      if (hasWildcard) {
        return { allowed: true, context: check.context };
      }

      return {
        allowed: false,
        deniedBy: 'permission',
        requiredPermissions: [requiredPermission],
        context: check.context,
      };
    } catch (error) {
      return {
        allowed: false,
        deniedBy: 'error',
        requiredPermissions: [`${check.resource}:${check.action}`],
      };
    }
  }

  async checkPermissions(checks: AuthorizationCheck[]): Promise<AuthorizationResult[]> {
    return Promise.all(checks.map(check => this.checkPermission(check)));
  }

  async hasRole(userId: string, roleName: string): Promise<boolean> {
    return this.userRoleStore.userHasRole(userId, roleName);
  }

  async hasAnyRole(userId: string, roleNames: string[]): Promise<boolean> {
    const userRoles = await this.userRoleStore.getUserRoles(userId);
    return roleNames.some(role => userRoles.includes(role));
  }

  async hasAllRoles(userId: string, roleNames: string[]): Promise<boolean> {
    const userRoles = await this.userRoleStore.getUserRoles(userId);
    return roleNames.every(role => userRoles.includes(role));
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    return this.userRoleStore.getUserPermissions(userId);
  }

  async getUserRoles(userId: string): Promise<string[]> {
    return this.userRoleStore.getUserRoles(userId);
  }

  async assignRole(userId: string, roleName: string): Promise<void> {
    return this.userRoleStore.assignRole(userId, roleName);
  }

  async revokeRole(userId: string, roleName: string): Promise<void> {
    return this.userRoleStore.revokeRole(userId, roleName);
  }
}
