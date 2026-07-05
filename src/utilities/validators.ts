export interface ValidationRule {
  field: string;
  type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'date' | 'array' | 'object';
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  enum?: string[];
  message?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export function validate(data: Record<string, unknown>, rules: ValidationRule[]): ValidationResult {
  const errors: ValidationError[] = [];

  for (const rule of rules) {
    const value = data[rule.field];

    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push({
        field: rule.field,
        message: rule.message ?? `${rule.field} is required`,
        code: 'REQUIRED',
      });
      continue;
    }

    if (value === undefined || value === null) continue;

    switch (rule.type) {
      case 'string':
        if (typeof value !== 'string') {
          errors.push({ field: rule.field, message: `${rule.field} must be a string`, code: 'INVALID_TYPE' });
        } else {
          if (rule.minLength && value.length < rule.minLength) {
            errors.push({ field: rule.field, message: `${rule.field} must be at least ${rule.minLength} characters`, code: 'MIN_LENGTH' });
          }
          if (rule.maxLength && value.length > rule.maxLength) {
            errors.push({ field: rule.field, message: `${rule.field} must be at most ${rule.maxLength} characters`, code: 'MAX_LENGTH' });
          }
          if (rule.pattern && !rule.pattern.test(value)) {
            errors.push({ field: rule.field, message: rule.message ?? `${rule.field} format is invalid`, code: 'PATTERN' });
          }
          if (rule.enum && !rule.enum.includes(value)) {
            errors.push({ field: rule.field, message: `${rule.field} must be one of: ${rule.enum.join(', ')}`, code: 'ENUM' });
          }
        }
        break;
      case 'email':
        if (typeof value !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          errors.push({ field: rule.field, message: rule.message ?? `${rule.field} must be a valid email`, code: 'INVALID_EMAIL' });
        }
        break;
      case 'number':
        if (typeof value !== 'number' || isNaN(value)) {
          errors.push({ field: rule.field, message: `${rule.field} must be a number`, code: 'INVALID_TYPE' });
        } else {
          if (rule.min !== undefined && value < rule.min) {
            errors.push({ field: rule.field, message: `${rule.field} must be at least ${rule.min}`, code: 'MIN' });
          }
          if (rule.max !== undefined && value > rule.max) {
            errors.push({ field: rule.field, message: `${rule.field} must be at most ${rule.max}`, code: 'MAX' });
          }
        }
        break;
      case 'url':
        if (typeof value !== 'string') {
          errors.push({ field: rule.field, message: `${rule.field} must be a URL`, code: 'INVALID_TYPE' });
        } else {
          try { new URL(value); } catch {
            errors.push({ field: rule.field, message: rule.message ?? `${rule.field} must be a valid URL`, code: 'INVALID_URL' });
          }
        }
        break;
      case 'boolean':
        if (typeof value !== 'boolean') {
          errors.push({ field: rule.field, message: `${rule.field} must be a boolean`, code: 'INVALID_TYPE' });
        }
        break;
      case 'array':
        if (!Array.isArray(value)) {
          errors.push({ field: rule.field, message: `${rule.field} must be an array`, code: 'INVALID_TYPE' });
        }
        break;
      case 'object':
        if (typeof value !== 'object' || Array.isArray(value) || value === null) {
          errors.push({ field: rule.field, message: `${rule.field} must be an object`, code: 'INVALID_TYPE' });
        }
        break;
    }
  }

  return { valid: errors.length === 0, errors };
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isValidPassword(password: string, minLength: number = 8): boolean {
  return password.length >= minLength;
}
