import { describe, it, expect } from 'vitest';
import {
  validateEmail, validateDisplayName, validateNewPassword,
  validatePasswordConfirmation, validateRegisterForm, validateLoginForm,
} from '../src/utils/validation.js';
import { scorePassword } from '../src/utils/passwordStrength.js';

describe('validation', () => {
  it('accepts a normal email and rejects bad ones', () => {
    expect(validateEmail('a@b.co')).toBeNull();
    expect(validateEmail('')).toMatch(/Enter your email/);
    expect(validateEmail('nope')).toMatch(/valid email/);
    expect(validateEmail('a@b')).toMatch(/valid email/);
  });
  it('checks display name length', () => {
    expect(validateDisplayName('Al')).toBeNull();
    expect(validateDisplayName('A')).not.toBeNull();
    expect(validateDisplayName('x'.repeat(61))).not.toBeNull();
  });
  it('enforces the minimum password length on register only', () => {
    expect(validateNewPassword('short')).not.toBeNull();
    expect(validateNewPassword('a'.repeat(12))).toBeNull();
    expect(validateLoginForm({ email: 'a@b.co', password: 'x' })).toEqual({});
  });
  it('checks password confirmation', () => {
    expect(validatePasswordConfirmation('abc', 'abd')).toMatch(/do not match/);
    expect(validatePasswordConfirmation('abc', 'abc')).toBeNull();
  });
  it('collects only failing fields', () => {
    const errs = validateRegisterForm({ displayName: '', email: 'a@b.co', password: 'a'.repeat(12), confirmation: 'a'.repeat(12) });
    expect(Object.keys(errs)).toEqual(['displayName']);
  });
});

describe('password strength', () => {
  it('scores weak, common and strong passwords sensibly', () => {
    expect(scorePassword('').score).toBe(0);
    expect(scorePassword('password123').score).toBeLessThanOrEqual(1);
    expect(scorePassword('aaaaaaaaaaaa').score).toBeLessThanOrEqual(2);
    expect(scorePassword('correct horse battery staple 9!').score).toBe(4);
  });
});
