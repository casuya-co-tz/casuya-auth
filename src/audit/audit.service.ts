import { v4 as uuid } from 'uuid';
import { AuditService, AuditEvent, AuditQuery } from './audit.service.interface';

export class DefaultAuditService implements AuditService {
  private readonly events: AuditEvent[] = [];
  private readonly retentionDays: number;

  constructor(retentionDays: number = 365) {
    this.retentionDays = retentionDays;
  }

  async record(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<AuditEvent> {
    const auditEvent: AuditEvent = {
      ...event,
      id: uuid(),
      timestamp: new Date(),
    };
    this.events.push(auditEvent);
    return auditEvent;
  }

  async query(query: AuditQuery): Promise<AuditEvent[]> {
    let results = [...this.events];

    if (query.userId) {
      results = results.filter(e => e.userId === query.userId);
    }
    if (query.eventType) {
      results = results.filter(e => e.eventType === query.eventType);
    }
    if (query.resource) {
      results = results.filter(e => e.resource === query.resource);
    }
    if (query.status) {
      results = results.filter(e => e.status === query.status);
    }
    if (query.startDate) {
      results = results.filter(e => e.timestamp >= query.startDate!);
    }
    if (query.endDate) {
      results = results.filter(e => e.timestamp <= query.endDate!);
    }

    results.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const page = query.page ?? 1;
    const limit = query.limit ?? 50;
    const start = (page - 1) * limit;
    return results.slice(start, start + limit);
  }

  async getById(eventId: string): Promise<AuditEvent | null> {
    return this.events.find(e => e.id === eventId) ?? null;
  }

  async getByUser(userId: string, page: number = 1, limit: number = 50): Promise<AuditEvent[]> {
    return this.query({ userId, page, limit });
  }

  async getByResource(resource: string, page: number = 1, limit: number = 50): Promise<AuditEvent[]> {
    return this.query({ resource, page, limit });
  }

  async getFailedEvents(page: number = 1, limit: number = 50): Promise<AuditEvent[]> {
    return this.query({ status: 'failure', page, limit });
  }

  async count(query: AuditQuery): Promise<number> {
    const results = await this.query({ ...query, page: 1, limit: Number.MAX_SAFE_INTEGER });
    return results.length;
  }

  async export(userId?: string, startDate?: Date, endDate?: Date): Promise<AuditEvent[]> {
    return this.query({ userId, startDate, endDate, page: 1, limit: Number.MAX_SAFE_INTEGER });
  }

  async getRetentionPeriod(): Promise<number> {
    return this.retentionDays;
  }
}
