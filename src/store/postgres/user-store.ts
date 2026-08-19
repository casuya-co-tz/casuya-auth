import { Pool, PoolConfig } from 'pg';
import { v4 as uuid } from 'uuid';
import { UserProfile } from '../../interfaces';

export interface PostgresUserStoreConfig extends PoolConfig {
  tableName?: string;
}

interface StoredUser {
  id: string;
  email: string;
  username: string;
  display_name: string;
  avatar_url: string | null;
  locale: string | null;
  timezone: string | null;
  metadata: Record<string, unknown> | null;
  password_hash: string;
  email_verified: boolean;
  created_at: Date;
  updated_at: Date;
}

export class PostgresUserStore {
  private pool: Pool;
  private tableName: string;

  constructor(config: PostgresUserStoreConfig) {
    const { tableName = 'casuya_users', ...poolConfig } = config;
    this.tableName = tableName;
    this.pool = new Pool({
      max: poolConfig.max ?? 20,
      idleTimeoutMillis: poolConfig.idleTimeoutMillis ?? 30000,
      connectionTimeoutMillis: poolConfig.connectionTimeoutMillis ?? 5000,
      ...poolConfig,
    });
  }

  async initialize(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(100) NOT NULL,
        display_name VARCHAR(255) NOT NULL,
        avatar_url TEXT,
        locale VARCHAR(10),
        timezone VARCHAR(50),
        metadata JSONB,
        password_hash VARCHAR(255) NOT NULL,
        email_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_email ON ${this.tableName}(email);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_username ON ${this.tableName}(username);
    `);
  }

  async create(user: { email: string; username: string; displayName: string; passwordHash: string; locale?: string; timezone?: string; metadata?: Record<string, unknown> }): Promise<UserProfile & { passwordHash: string }> {
    const id = uuid();
    const result = await this.pool.query(
      `INSERT INTO ${this.tableName} (id, email, username, display_name, password_hash, locale, timezone, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [id, user.email.toLowerCase(), user.username, user.displayName, user.passwordHash, user.locale ?? null, user.timezone ?? null, user.metadata ? JSON.stringify(user.metadata) : null]
    );
    return this.rowToUser(result.rows[0]);
  }

  async findById(id: string): Promise<(UserProfile & { passwordHash: string }) | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE id = $1`, [id]);
    if (result.rows.length === 0) return null;
    return this.rowToUser(result.rows[0]);
  }

  async findByEmail(email: string): Promise<(UserProfile & { passwordHash: string }) | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE email = $1`, [email.toLowerCase()]);
    if (result.rows.length === 0) return null;
    return this.rowToUser(result.rows[0]);
  }

  async findByUsername(username: string): Promise<(UserProfile & { passwordHash: string }) | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE username = $1`, [username]);
    if (result.rows.length === 0) return null;
    return this.rowToUser(result.rows[0]);
  }

  async update(id: string, updates: Partial<UserProfile>): Promise<boolean> {
    const fields: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (updates.email !== undefined) { fields.push(`email = $${idx++}`); values.push(updates.email.toLowerCase()); }
    if (updates.username !== undefined) { fields.push(`username = $${idx++}`); values.push(updates.username); }
    if (updates.displayName !== undefined) { fields.push(`display_name = $${idx++}`); values.push(updates.displayName); }
    if (updates.avatarUrl !== undefined) { fields.push(`avatar_url = $${idx++}`); values.push(updates.avatarUrl); }
    if (updates.locale !== undefined) { fields.push(`locale = $${idx++}`); values.push(updates.locale); }
    if (updates.timezone !== undefined) { fields.push(`timezone = $${idx++}`); values.push(updates.timezone); }
    if (updates.metadata !== undefined) { fields.push(`metadata = $${idx++}`); values.push(JSON.stringify(updates.metadata)); }

    if (fields.length === 0) return false;
    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await this.pool.query(
      `UPDATE ${this.tableName} SET ${fields.join(', ')} WHERE id = $${idx}`,
      values
    );
    return (result.rowCount ?? 0) > 0;
  }

  async updatePassword(id: string, passwordHash: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE ${this.tableName} SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
      [passwordHash, id]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.pool.query(`DELETE FROM ${this.tableName} WHERE id = $1`, [id]);
    return (result.rowCount ?? 0) > 0;
  }

  async count(): Promise<number> {
    const result = await this.pool.query(`SELECT COUNT(*) as count FROM ${this.tableName}`);
    return parseInt(result.rows[0].count, 10);
  }

  async list(offset = 0, limit = 100): Promise<UserProfile[]> {
    const result = await this.pool.query(
      `SELECT * FROM ${this.tableName} ORDER BY created_at DESC OFFSET $1 LIMIT $2`,
      [offset, limit]
    );
    return result.rows.map(r => this.rowToUser(r));
  }

  async search(query: string): Promise<UserProfile[]> {
    const result = await this.pool.query(
      `SELECT * FROM ${this.tableName}
       WHERE display_name ILIKE $1 OR email ILIKE $1 OR username ILIKE $1
       LIMIT 50`,
      [`%${query}%`]
    );
    return result.rows.map(r => this.rowToUser(r));
  }

  private rowToUser(row: StoredUser): UserProfile & { passwordHash: string } {
    return {
      id: row.id,
      email: row.email,
      username: row.username,
      displayName: row.display_name,
      avatarUrl: row.avatar_url ?? undefined,
      locale: row.locale ?? undefined,
      timezone: row.timezone ?? undefined,
      metadata: row.metadata ?? undefined,
      passwordHash: row.password_hash,
    };
  }

  async shutdown(): Promise<void> {
    await this.pool.end();
  }
}
