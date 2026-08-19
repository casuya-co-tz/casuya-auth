import Redis from 'ioredis';
import { Session, SessionStore } from '../../interfaces';

export interface RedisSessionStoreConfig {
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
  defaultTtlSeconds?: number;
  client?: Redis;
}

export class RedisSessionStore implements SessionStore {
  private redis: Redis;
  private keyPrefix: string;

  constructor(config: RedisSessionStoreConfig = {}) {
    this.keyPrefix = config.keyPrefix ?? 'casuya:session:';

    if (config.client) {
      this.redis = config.client;
    } else {
      this.redis = new Redis({
        host: config.host ?? '127.0.0.1',
        port: config.port ?? 6379,
        password: config.password,
        db: config.db ?? 0,
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: true,
      });
    }
  }

  async connect(): Promise<void> {
    if (this.redis.status !== 'ready') {
      await this.redis.connect();
    }
  }

  async create(session: Session): Promise<Session> {
    const ttl = Math.max(1, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000));
    const data = JSON.stringify(session);

    const pipeline = this.redis.pipeline();
    pipeline.set(this.keyPrefix + session.id, data, 'EX', ttl);
    pipeline.set(this.keyPrefix + 'token:' + session.token, session.id, 'EX', ttl);
    pipeline.set(this.keyPrefix + 'refresh:' + session.refreshToken, session.id, 'EX', ttl);
    pipeline.set(this.keyPrefix + 'user:' + session.userId, session.id, 'EX', ttl);
    await pipeline.exec();

    return session;
  }

  async findById(sessionId: string): Promise<Session | null> {
    const data = await this.redis.get(this.keyPrefix + sessionId);
    if (!data) return null;
    const session = JSON.parse(data) as Session;
    if (new Date(session.expiresAt) < new Date()) return null;
    return session;
  }

  async findByToken(token: string): Promise<Session | null> {
    const sessionId = await this.redis.get(this.keyPrefix + 'token:' + token);
    if (!sessionId) return null;
    return this.findById(sessionId);
  }

  async findByRefreshToken(refreshToken: string): Promise<Session | null> {
    const sessionId = await this.redis.get(this.keyPrefix + 'refresh:' + refreshToken);
    if (!sessionId) return null;
    return this.findById(sessionId);
  }

  async findByUserId(userId: string): Promise<Session[]> {
    const sessionId = await this.redis.get(this.keyPrefix + 'user:' + userId);
    if (!sessionId) return [];
    const session = await this.findById(sessionId);
    return session ? [session] : [];
  }

  async invalidate(sessionId: string): Promise<void> {
    const data = await this.redis.get(this.keyPrefix + sessionId);
    if (data) {
      const session = JSON.parse(data) as Session;
      const pipeline = this.redis.pipeline();
      pipeline.del(this.keyPrefix + sessionId);
      pipeline.del(this.keyPrefix + 'token:' + session.token);
      pipeline.del(this.keyPrefix + 'refresh:' + session.refreshToken);
      pipeline.del(this.keyPrefix + 'user:' + session.userId);
      await pipeline.exec();
    }
  }

  async invalidateAllForUser(userId: string): Promise<void> {
    const sessionId = await this.redis.get(this.keyPrefix + 'user:' + userId);
    if (sessionId) {
      await this.invalidate(sessionId);
    }
  }

  async updateActivity(sessionId: string): Promise<void> {
    const data = await this.redis.get(this.keyPrefix + sessionId);
    if (data) {
      const session = JSON.parse(data) as Session;
      session.lastActivityAt = new Date();
      const ttl = await this.redis.ttl(this.keyPrefix + sessionId);
      if (ttl > 0) {
        await this.redis.set(this.keyPrefix + sessionId, JSON.stringify(session), 'EX', ttl);
      }
    }
  }

  async deleteExpired(): Promise<number> {
    let count = 0;
    let cursor = '0';
    do {
      const [nextCursor, keys] = await this.redis.scan(cursor, 'MATCH', this.keyPrefix + '*', 'COUNT', 100);
      cursor = nextCursor;
      for (const key of keys) {
        const ttl = await this.redis.ttl(key);
        if (ttl <= 0) {
          await this.redis.del(key);
          count++;
        }
      }
    } while (cursor !== '0');
    return count;
  }

  async incrementRateLimit(key: string, windowMs: number): Promise<{ count: number; ttl: number }> {
    const fullKey = this.keyPrefix + 'ratelimit:' + key;
    const count = await this.redis.incr(fullKey);
    if (count === 1) {
      await this.redis.pexpire(fullKey, windowMs);
    }
    const ttl = await this.redis.pttl(fullKey);
    return { count, ttl: Math.max(0, ttl) };
  }

  async shutdown(): Promise<void> {
    this.redis.disconnect();
  }
}
