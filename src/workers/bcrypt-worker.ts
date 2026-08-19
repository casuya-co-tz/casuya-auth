import { parentPort } from 'worker_threads';
import bcrypt from 'bcrypt';

interface BcryptWorkerMessage {
  id: string;
  action: 'hash' | 'compare';
  password?: string;
  hash?: string;
  passwordHash?: string;
  saltRounds?: number;
}

if (parentPort) {
  parentPort.on('message', async (msg: BcryptWorkerMessage) => {
    try {
      if (msg.action === 'hash' && msg.password) {
        const hash = await bcrypt.hash(msg.password, msg.saltRounds ?? 12);
        parentPort!.postMessage({ id: msg.id, result: hash, error: null });
      } else if (msg.action === 'compare' && msg.password && msg.passwordHash) {
        const valid = await bcrypt.compare(msg.password, msg.passwordHash);
        parentPort!.postMessage({ id: msg.id, result: valid, error: null });
      } else {
        parentPort!.postMessage({ id: msg.id, result: null, error: 'Invalid action or missing parameters' });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      parentPort!.postMessage({ id: msg.id, result: null, error: message });
    }
  });
}
