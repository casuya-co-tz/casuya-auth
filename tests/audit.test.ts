import { DefaultAuditService } from '../src/audit';
import { AuditEventType } from '../src/audit';

describe('DefaultAuditService', () => {
  let auditService: DefaultAuditService;

  beforeEach(() => {
    auditService = new DefaultAuditService(90);
  });

  it('should record an audit event', async () => {
    const event = await auditService.record({
      eventType: AuditEventType.LOGIN,
      userId: 'user-1',
      status: 'success',
    });
    expect(event.id).toBeDefined();
    expect(event.timestamp).toBeInstanceOf(Date);
    expect(event.eventType).toBe(AuditEventType.LOGIN);
  });

  it('should query events by user', async () => {
    await auditService.record({ eventType: AuditEventType.LOGIN, userId: 'user-1', status: 'success' });
    await auditService.record({ eventType: AuditEventType.LOGOUT, userId: 'user-1', status: 'success' });
    await auditService.record({ eventType: AuditEventType.LOGIN, userId: 'user-2', status: 'success' });

    const events = await auditService.getByUser('user-1');
    expect(events).toHaveLength(2);
  });

  it('should query events by resource', async () => {
    await auditService.record({ eventType: AuditEventType.ROLE_ASSIGN, userId: 'user-1', resource: 'roles:admin', status: 'success' });
    const events = await auditService.getByResource('roles:admin');
    expect(events).toHaveLength(1);
  });

  it('should get failed events', async () => {
    await auditService.record({ eventType: AuditEventType.LOGIN_FAILED, userId: 'user-1', status: 'failure' });
    await auditService.record({ eventType: AuditEventType.LOGIN, userId: 'user-1', status: 'success' });

    const failed = await auditService.getFailedEvents();
    expect(failed).toHaveLength(1);
    expect(failed[0].status).toBe('failure');
  });

  it('should return retention period', async () => {
    const days = await auditService.getRetentionPeriod();
    expect(days).toBe(90);
  });
});
