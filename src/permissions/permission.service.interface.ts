import { Permission, PermissionCheck } from '../interfaces';

export interface PermissionService {
  createPermission(permission: Omit<Permission, 'id' | 'createdAt' | 'isSystem'>): Promise<Permission>;
  getPermission(permissionId: string): Promise<Permission | null>;
  getPermissionByName(name: string): Promise<Permission | null>;
  getAllPermissions(): Promise<Permission[]>;
  getPermissionsByResource(resource: string): Promise<Permission[]>;
  deletePermission(permissionId: string): Promise<void>;
  hasPermission(check: PermissionCheck): Promise<boolean>;
  hasPermissions(checks: PermissionCheck[]): Promise<boolean[]>;
  grantPermission(userId: string, permissionName: string): Promise<void>;
  revokePermission(userId: string, permissionName: string): Promise<void>;
}
