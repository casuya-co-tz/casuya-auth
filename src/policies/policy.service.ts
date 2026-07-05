import { v4 as uuid } from 'uuid';
import { PolicyService, Policy, PolicyRule, PolicyCondition, PolicyEvaluationRequest, PolicyEvaluationResult } from './policy.service.interface';
import { PermissionAction } from '../interfaces';

export class DefaultPolicyService implements PolicyService {
  private readonly policies: Policy[] = [];

  async createPolicy(policy: Omit<Policy, 'id' | 'createdAt' | 'updatedAt'>): Promise<Policy> {
    const newPolicy: Policy = {
      ...policy,
      id: uuid(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.policies.push(newPolicy);
    return newPolicy;
  }

  async updatePolicy(policyId: string, updates: Partial<Policy>): Promise<Policy> {
    const index = this.policies.findIndex(p => p.id === policyId);
    if (index === -1) throw new Error(`Policy ${policyId} not found`);
    this.policies[index] = {
      ...this.policies[index],
      ...updates,
      id: policyId,
      updatedAt: new Date(),
    };
    return this.policies[index];
  }

  async deletePolicy(policyId: string): Promise<void> {
    const index = this.policies.findIndex(p => p.id === policyId);
    if (index !== -1) this.policies.splice(index, 1);
  }

  async getPolicy(policyId: string): Promise<Policy | null> {
    return this.policies.find(p => p.id === policyId) ?? null;
  }

  async getAllPolicies(): Promise<Policy[]> {
    return [...this.policies].sort((a, b) => a.priority - b.priority);
  }

  async evaluate(request: PolicyEvaluationRequest): Promise<PolicyEvaluationResult> {
    const evaluationChain: PolicyEvaluationResult['evaluationChain'] = [];
    const sortedPolicies = [...this.policies]
      .filter(p => p.isEnabled)
      .sort((a, b) => a.priority - b.priority);

    for (const policy of sortedPolicies) {
      for (const rule of policy.rules) {
        const matched = this.evaluateRule(rule, request);
        evaluationChain.push({
          policyId: policy.id,
          policyName: policy.name,
          ruleId: rule.id,
          ruleName: rule.name,
          effect: rule.effect,
          matched,
        });

        if (matched) {
          return {
            allowed: rule.effect === 'allow',
            matchedRule: rule,
            matchedPolicy: policy,
            evaluationChain,
          };
        }
      }
    }

    return { allowed: false, evaluationChain };
  }

  async evaluateBatch(requests: PolicyEvaluationRequest[]): Promise<PolicyEvaluationResult[]> {
    return Promise.all(requests.map(req => this.evaluate(req)));
  }

  private evaluateRule(rule: PolicyRule, request: PolicyEvaluationRequest): boolean {
    const resourceMatch = rule.resources.some(r => {
      if (r === '*') return true;
      if (r.endsWith('*')) {
        return request.resource.startsWith(r.slice(0, -1));
      }
      return r === request.resource;
    });

    if (!resourceMatch) return false;

    const actionMatch = rule.actions.some(a => {
      if (a === PermissionAction.MANAGE) return true;
      return a === request.action;
    });

    if (!actionMatch) return false;

    if (rule.conditions && rule.conditions.length > 0) {
      return rule.conditions.every(condition => this.evaluateCondition(condition, request.context ?? {}));
    }

    return true;
  }

  private evaluateCondition(condition: PolicyCondition, context: Record<string, unknown>): boolean {
    const value = context[condition.field];

    switch (condition.operator) {
      case 'eq': return value === condition.value;
      case 'neq': return value !== condition.value;
      case 'gt': return typeof value === 'number' && typeof condition.value === 'number' && value > condition.value;
      case 'gte': return typeof value === 'number' && typeof condition.value === 'number' && value >= condition.value;
      case 'lt': return typeof value === 'number' && typeof condition.value === 'number' && value < condition.value;
      case 'lte': return typeof value === 'number' && typeof condition.value === 'number' && value <= condition.value;
      case 'in': return Array.isArray(condition.value) && condition.value.includes(value);
      case 'nin': return Array.isArray(condition.value) && !condition.value.includes(value);
      case 'contains': return typeof value === 'string' && typeof condition.value === 'string' && value.includes(condition.value as string);
      case 'exists': return (condition.value === true && value !== undefined) || (condition.value === false && value === undefined);
      default: return false;
    }
  }
}
