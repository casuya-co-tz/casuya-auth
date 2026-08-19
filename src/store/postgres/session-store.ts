import { Pool, PoolConfig } from 'pg';
import { Session, SessionStore } from '../../interfaces';

export interface PostgresSessionStoreConfig extends PoolConfig {
  tableName?: string;
}

export class PostgresSessionStore implements SessionStore {
  private pool: Pool;
  private tableName: string;

  constructor(config: PostgresSessionStoreConfig) {
    const { tableName = 'casuya_sessions', ...poolConfig } = config;
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
        user_id VARCHAR(36) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        refresh_token VARCHAR(255) UNIQUE NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        device_id VARCHAR(255),
        is_valid BOOLEAN DEFAULT TRUE,
        issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        metadata JSONB
      );
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_user_id ON ${this.tableName}(user_id);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_token ON ${this.tableName}(token);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_refresh_token ON ${this.tableName}(refresh_token);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expires_at ON ${this.tableName}(expires_at);
    `);
  }

  async create(session: Session): Promise<Session> {
    await this.pool.query(
      `INSERT INTO ${this.tableName} (id, user_id, token, refresh_token, ip_address, user_agent, device_id, is_valid, issued_at, expires_at, last_activity_at, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        session.id, session.userId, session.token, session.refreshToken,
        session.ipAddress ?? null, session.userAgent ?? null, session.deviceId ?? null,
        session.isValid, session.issuedAt, session.expiresAt, session.lastActivityAt,
        session.metadata ? JSON.stringify(session.metadata) : null,
      ]
    );
    return session;
  }

  async findById(sessionId: string): Promise<Session | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE id = $1`, [sessionId]);
    if (result.rows.length === 0) return null;
    return this.rowToSession(result.rows[0]);
  }

  async findByToken(token: string): Promise<Session | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE token = $1 AND is_valid = TRUE`, [token]);
    if (result.rows.length === 0) return null;
    return this.rowToSession(result.rows[0]);
  }

  async findByRefreshToken(refreshToken: string): Promise<Session | null> {
    const result = await this.pool.query(`SELECT * FROM ${this.tableName} WHERE refresh_token = $1 AND is_valid = TRUE`, [refreshToken]);
    if (result.rows.length === 0) return null;
    return this.rowToSession(result.rows[0]);
  }

  async findByUserId(userId: string): Promise<Session[]> {
    const result = await this.pool.query(
      `SELECT * FROM ${this.tableName} WHERE user_id = $1 AND is_valid = TRUE ORDER BY last_activity_at DESC`,
      [userId]
    );
    return result.rows.map(r => this.rowToSession(r));
  }

  async invalidate(sessionId: string): Promise<void> {
    await this.pool.query(`UPDATE ${this.tableName} SET is_valid = FALSE WHERE id = $1`, [sessionId]);
  }

  async invalidateAllForUser(userId: string): Promise<void> {
    await this.pool.query(`UPDATE ${this.tableName} SET is_valid = FALSE WHERE user_id = $1`, [userId]);
  }

  async updateActivity(sessionId: string): Promise<void> {
    await this.pool.query(`UPDATE ${this.tableName} SET last_activity_at = NOW() WHERE id = $1`, [sessionId]);
  }

  async deleteExpired(): Promise<number> {
    const result = await this.pool.query(`DELETE FROM ${this.tableName} WHERE expires_at < NOW() OR is_valid = FALSE`);
    return result.rowCount ?? 0;
  }

  async count(): Promise<number> {
    const result = await this.pool.query(`SELECT COUNT(*) as count FROM ${this.tableName} WHERE is_valid = TRUE`);
    return parseInt(result.rows[0].count, 10);
  }

  async shutdown(): Promise<void> {
    await this.pool.end();
  }

  private rowToSession(row: any): Session {
    return {
      id: row.id,
      userId: row.user_id,
      token: row.token,
      refreshToken: row.refresh_token,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      deviceId: row.device_id,
      isValid: row.is_valid,
      issuedAt: new Date(row.issued_at),
      expiresAt: new Date(row.expires_at),
      lastActivityAt: new Date(row.last_activity_at),
      metadata: row.metadata,
    };
  }
}
