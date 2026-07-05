import { PermissionAction } from '../interfaces';

export interface PolicyCondition {
  field: string;
  operator: 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'nin' | 'contains' | 'exists';
  value: unknown;
}

export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  effect: 'allow' | 'deny';
  resources: string[];
  actions: PermissionAction[];
  conditions?: PolicyCondition[];
  priority: number;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  isEnabled: boolean;
  priority: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyEvaluationRequest {
  userId: string;
  resource: string;
  action: PermissionAction;
  context?: Record<string, unknown>;
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  matchedRule?: PolicyRule;
  matchedPolicy?: Policy;
  evaluationChain: Array<{
    policyId: string;
    policyName: string;
    ruleId: string;
    ruleName: string;
    effect: string;
    matched: boolean;
  }>;
}

export interface PolicyService {
  createPolicy(policy: Omit<Policy, 'id' | 'createdAt' | 'updatedAt'>): Promise<Policy>;
  updatePolicy(policyId: string, updates: Partial<Policy>): Promise<Policy>;
  deletePolicy(policyId: string): Promise<void>;
  getPolicy(policyId: string): Promise<Policy | null>;
  getAllPolicies(): Promise<Policy[]>;
  evaluate(request: PolicyEvaluationRequest): Promise<PolicyEvaluationResult>;
  evaluateBatch(requests: PolicyEvaluationRequest[]): Promise<PolicyEvaluationResult[]>;
}
