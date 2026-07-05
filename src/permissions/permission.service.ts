import { v4 as uuid } from 'uuid';
import { PermissionService } from './permission.service.interface';
import { Permission, PermissionAction, PermissionCheck, PermissionStore } from '../interfaces';

export interface UserPermissionStore {
  userHasPermission(userId: string, permissionName: string): Promise<boolean>;
  grantPermission(userId: string, permissionName: string): Promise<void>;
  revokePermission(userId: string, permissionName: string): Promise<void>;
  getUserPermissions(userId: string): Promise<string[]>;
}

export class DefaultPermissionService implements PermissionService {
  private readonly permissionStore: PermissionStore;
  private readonly userPermissionStore: UserPermissionStore;

  constructor(permissionStore: PermissionStore, userPermissionStore: UserPermissionStore) {
    this.permissionStore = permissionStore;
    this.userPermissionStore = userPermissionStore;
  }

  async createPermission(data: Omit<Permission, 'id' | 'createdAt' | 'isSystem'>): Promise<Permission> {
    const exists = await this.permissionStore.exists(data.name);
    if (exists) {
      throw new Error(`Permission ${data.name} already exists`);
    }
    const permission: Permission = {
      ...data,
      id: uuid(),
      isSystem: false,
      createdAt: new Date(),
    };
    return this.permissionStore.create(permission);
  }

  async getPermission(permissionId: string): Promise<Permission | null> {
    return this.permissionStore.findById(permissionId);
  }

  async getPermissionByName(name: string): Promise<Permission | null> {
    return this.permissionStore.findByName(name);
  }

  async getAllPermissions(): Promise<Permission[]> {
    return this.permissionStore.findAll();
  }

  async getPermissionsByResource(resource: string): Promise<Permission[]> {
    return this.permissionStore.findByResource(resource);
  }

  async deletePermission(permissionId: string): Promise<void> {
    return this.permissionStore.delete(permissionId);
  }

  async hasPermission(check: PermissionCheck): Promise<boolean> {
    const permissionName = `${check.resource}:${check.action}`;
    return this.userPermissionStore.userHasPermission(check.userId, permissionName);
  }

  async hasPermissions(checks: PermissionCheck[]): Promise<boolean[]> {
    return Promise.all(checks.map(check => this.hasPermission(check)));
  }

  async grantPermission(userId: string, permissionName: string): Promise<void> {
    const exists = await this.permissionStore.exists(permissionName);
    if (!exists) {
      const [resource, action] = permissionName.split(':');
      await this.createPermission({
        name: permissionName,
        resource: resource ?? 'unknown',
        action: (action as PermissionAction) ?? PermissionAction.READ,
        description: `Auto-created permission: ${permissionName}`,
      });
    }
    return this.userPermissionStore.grantPermission(userId, permissionName);
  }

  async revokePermission(userId: string, permissionName: string): Promise<void> {
    return this.userPermissionStore.revokePermission(userId, permissionName);
  }
}
