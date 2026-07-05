import { PermissionAction } from '../interfaces';

export interface AuthorizationCheck {
  userId: string;
  resource: string;
  action: PermissionAction;
  context?: Record<string, unknown>;
}

export interface AuthorizationResult {
  allowed: boolean;
  deniedBy?: string;
  requiredPermissions?: string[];
  context?: Record<string, unknown>;
}

export interface AuthorizationService {
  checkPermission(check: AuthorizationCheck): Promise<AuthorizationResult>;
  checkPermissions(checks: AuthorizationCheck[]): Promise<AuthorizationResult[]>;
  hasRole(userId: string, roleName: string): Promise<boolean>;
  hasAnyRole(userId: string, roleNames: string[]): Promise<boolean>;
  hasAllRoles(userId: string, roleNames: string[]): Promise<boolean>;
  getUserPermissions(userId: string): Promise<string[]>;
  getUserRoles(userId: string): Promise<string[]>;
  assignRole(userId: string, roleName: string): Promise<void>;
  revokeRole(userId: string, roleName: string): Promise<void>;
}
