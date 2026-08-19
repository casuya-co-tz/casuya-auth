export interface RateLimitRule {
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  total: number;
}

export interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<{ count: number; ttl: number }>;
}

export class SlidingWindowRateLimiter {
  private rules: Map<string, RateLimitRule> = new Map();
  private counters: Map<string, { count: number; windowStart: number }> = new Map();
  private store: RateLimitStore | null;

  constructor(store?: RateLimitStore) {
    this.store = store ?? null;
    this.rules.set('login', { windowMs: 15 * 60 * 1000, maxRequests: 10 });
    this.rules.set('api', { windowMs: 60 * 1000, maxRequests: 100 });
    this.rules.set('registration', { windowMs: 60 * 60 * 1000, maxRequests: 5 });
    this.rules.set('password-reset', { windowMs: 60 * 60 * 1000, maxRequests: 3 });
  }

  setRule(name: string, rule: RateLimitRule): void {
    this.rules.set(name, rule);
  }

  async check(ruleName: string, identifier: string): Promise<RateLimitResult> {
    const rule = this.rules.get(ruleName);
    if (!rule) return { allowed: true, remaining: Infinity, resetAt: new Date(), total: Infinity };

    if (this.store) {
      return this.checkWithStore(ruleName, identifier, rule);
    }
    return this.checkLocal(ruleName, identifier, rule);
  }

  private async checkWithStore(ruleName: string, identifier: string, rule: RateLimitRule): Promise<RateLimitResult> {
    const key = `${rule.keyPrefix ?? ruleName}:${identifier}`;
    const { count, ttl } = await this.store!.increment(key, rule.windowMs);
    const allowed = count <= rule.maxRequests;
    return {
      allowed,
      remaining: Math.max(0, rule.maxRequests - count),
      resetAt: new Date(Date.now() + (ttl > 0 ? ttl : rule.windowMs)),
      total: rule.maxRequests,
    };
  }

  private checkLocal(ruleName: string, identifier: string, rule: RateLimitRule): RateLimitResult {
    const key = `${rule.keyPrefix ?? ruleName}:${identifier}`;
    const now = Date.now();
    const entry = this.counters.get(key);

    if (!entry || now - entry.windowStart > rule.windowMs) {
      this.counters.set(key, { count: 1, windowStart: now });
      return { allowed: true, remaining: rule.maxRequests - 1, resetAt: new Date(now + rule.windowMs), total: rule.maxRequests };
    }

    entry.count++;
    const remaining = rule.maxRequests - entry.count;
    return {
      allowed: remaining >= 0,
      remaining: Math.max(0, remaining),
      resetAt: new Date(entry.windowStart + rule.windowMs),
      total: rule.maxRequests,
    };
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [key, entry] of this.counters) {
      const rule = this.rules.get(key.split(':')[0]);
      if (rule && now - entry.windowStart > rule.windowMs) {
        this.counters.delete(key);
      }
    }
  }

  getRules(): Map<string, RateLimitRule> {
    return new Map(this.rules);
  }
}
