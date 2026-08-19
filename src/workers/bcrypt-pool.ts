import { Worker } from 'worker_threads';
import { randomUUID } from 'crypto';
import * as path from 'path';
import * as os from 'os';

interface PendingRequest {
  id: string;
  resolve: (value: string | boolean) => void;
  reject: (reason: Error) => void;
}

export interface BcryptWorkerPoolConfig {
  poolSize?: number;
  saltRounds?: number;
}

export class BcryptWorkerPool {
  private workers: Worker[] = [];
  private pending: Map<string, PendingRequest> = new Map();
  private nextWorker = 0;
  private saltRounds: number;
  private initialized = false;

  constructor(config: BcryptWorkerPoolConfig = {}) {
    this.saltRounds = config.saltRounds ?? 12;
    const poolSize = config.poolSize ?? Math.min(8, os.cpus().length || 4);
    const workerPath = path.join(__dirname, 'bcrypt-worker.js');

    for (let i = 0; i < poolSize; i++) {
      const worker = new Worker(workerPath);
      worker.on('message', (msg: { id: string; result: string | boolean; error: string | null }) => {
        const req = this.pending.get(msg.id);
        if (req) {
          this.pending.delete(msg.id);
          if (msg.error) {
            req.reject(new Error(msg.error));
          } else {
            req.resolve(msg.result);
          }
        }
      });
      worker.on('error', () => {});
      this.workers.push(worker);
    }
    this.initialized = true;
  }

  hash(password: string): Promise<string> {
    return this.dispatch({ action: 'hash', password, saltRounds: this.saltRounds }) as Promise<string>;
  }

  compare(password: string, passwordHash: string): Promise<boolean> {
    return this.dispatch({ action: 'compare', password, passwordHash }) as Promise<boolean>;
  }

  private dispatch(message: { action: string; password: string; saltRounds?: number; passwordHash?: string }): Promise<string | boolean> {
    if (!this.initialized || this.workers.length === 0) {
      const bcrypt = require('bcrypt') as typeof import('bcrypt');
      if (message.action === 'hash') {
        return bcrypt.hash(message.password, message.saltRounds ?? this.saltRounds);
      }
      return bcrypt.compare(message.password, message.passwordHash!);
    }

    return new Promise((resolve, reject) => {
      const id = randomUUID();
      this.pending.set(id, { id, resolve, reject });

      const worker = this.workers[this.nextWorker % this.workers.length];
      this.nextWorker++;

      worker.postMessage({ id, ...message });

      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error('Bcrypt worker timeout'));
        }
      }, 30000);
    });
  }

  async shutdown(): Promise<void> {
    const shutdowns = this.workers.map(w => w.terminate());
    await Promise.all(shutdowns);
    this.workers = [];
    this.initialized = false;
    for (const [, req] of this.pending) {
      req.reject(new Error('Worker pool shut down'));
    }
    this.pending.clear();
  }

  get poolSize(): number {
    return this.workers.length;
  }

  get pendingCount(): number {
    return this.pending.size;
  }
}
