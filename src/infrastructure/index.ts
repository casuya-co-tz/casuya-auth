import { PostgresUserStore, PostgresUserStoreConfig } from '../store/postgres/user-store';
import { PostgresSessionStore, PostgresSessionStoreConfig } from '../store/postgres/session-store';
import { RedisSessionStore, RedisSessionStoreConfig } from '../store/redis/session-store';
import { BcryptWorkerPool, BcryptWorkerPoolConfig } from '../workers/bcrypt-pool';
import { SlidingWindowRateLimiter } from '../rate-limit/rate-limiter';
import { RateLimitStore } from '../rate-limit/rate-limiter';
import { SessionStore } from '../interfaces';

export interface AuthInfrastructureConfig {
  postgres?: PostgresUserStoreConfig & PostgresSessionStoreConfig & { enabled?: boolean };
  redis?: RedisSessionStoreConfig & { enabled?: boolean; sessionFallbackToPostgres?: boolean };
  bcrypt?: BcryptWorkerPoolConfig;
  rateLimit?: { enabled?: boolean };
}

export interface AuthInfrastructureComponents {
  userStore: PostgresUserStore;
  sessionStore: SessionStore;
  bcryptPool: BcryptWorkerPool;
  rateLimiter: SlidingWindowRateLimiter;
  shutdown: () => Promise<void>;
}

export function createAuthInfrastructure(config: AuthInfrastructureConfig): AuthInfrastructureComponents {
  const userStore = new PostgresUserStore(config.postgres ?? {});

  let sessionStore: SessionStore;
  let redisStore: RedisSessionStore | null = null;
  let rateLimitStore: RateLimitStore | null = null;

  if (config.redis?.enabled) {
    redisStore = new RedisSessionStore(config.redis);
    sessionStore = redisStore;
    rateLimitStore = {
      increment: async (key: string, windowMs: number) => {
        return redisStore!.incrementRateLimit(key, windowMs);
      },
    };
  } else {
    sessionStore = new PostgresSessionStore(config.postgres ?? {});
  }

  const bcryptPool = new BcryptWorkerPool(config.bcrypt);
  const rateLimiter = new SlidingWindowRateLimiter(rateLimitStore ?? undefined);

  const shutdown = async () => {
    const tasks: Promise<void>[] = [bcryptPool.shutdown(), userStore.shutdown()];
    if (redisStore) tasks.push(redisStore.shutdown());
    if (sessionStore instanceof PostgresSessionStore) tasks.push(sessionStore.shutdown());
    await Promise.all(tasks);
  };

  return { userStore, sessionStore, bcryptPool, rateLimiter, shutdown };
}

export async function initializeAuthInfrastructure(components: AuthInfrastructureComponents): Promise<void> {
  await components.userStore.initialize();
  if (components.sessionStore instanceof PostgresSessionStore) {
    await components.sessionStore.initialize();
  }
}
