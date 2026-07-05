export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: PermissionAction;
  description?: string;
  isSystem: boolean;
  createdAt: Date;
}

export enum PermissionAction {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  MANAGE = 'manage',
  EXECUTE = 'execute',
}

export interface PermissionStore {
  create(permission: Permission): Promise<Permission>;
  findById(permissionId: string): Promise<Permission | null>;
  findByName(name: string): Promise<Permission | null>;
  findAll(): Promise<Permission[]>;
  findByResource(resource: string): Promise<Permission[]>;
  delete(permissionId: string): Promise<void>;
  exists(name: string): Promise<boolean>;
}

export interface PermissionCheck {
  userId: string;
  resource: string;
  action: PermissionAction;
  context?: Record<string, unknown>;
}
