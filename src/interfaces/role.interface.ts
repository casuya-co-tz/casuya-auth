export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  isSystem: boolean;
  isMutable: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissions: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

export interface RoleStore {
  create(role: Role): Promise<Role>;
  findById(roleId: string): Promise<Role | null>;
  findByName(name: string): Promise<Role | null>;
  findAll(): Promise<Role[]>;
  update(roleId: string, updates: UpdateRoleRequest): Promise<Role>;
  delete(roleId: string): Promise<void>;
  addPermission(roleId: string, permission: string): Promise<void>;
  removePermission(roleId: string, permission: string): Promise<void>;
  getPermissionsForRole(roleId: string): Promise<string[]>;
}
