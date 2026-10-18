import { describe, it, expect, beforeEach } from 'vitest';
import { authApi } from '../src/services/authApi.js';
import { __resetMockAuth, __setMockLatency, DEMO_USER } from '../src/services/mock/mockAuthApi.js';
import { prepareLogin, prepareRegistration } from '../src/services/cryptoBridge.js';
import { checkRegisterRequest, isLoginResponse, isRegisterResponse } from '../src/services/contract.js';

beforeEach(() => {
  __resetMockAuth();
  __setMockLatency(0);
});

async function registerBody(email, password = 'a-long-test-password') {
  return { email, displayName: 'Test User', ...(await prepareRegistration(password, email)) };
}

describe('mock auth API matches the API Agreements sheet', () => {
  it('registration payload built by the UI satisfies the contract', async () => {
    expect(checkRegisterRequest(await registerBody('x@y.co'))).toEqual([]);
  });

  it('register returns { userId, sessionToken }', async () => {
    const res = await authApi.register(await registerBody('x@y.co'));
    expect(isRegisterResponse(res)).toBe(true);
    expect(res.userId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('login returns { userId, sessionToken, kdfSalt, wrappedPrivateKey }', async () => {
    const { authSecret } = await prepareLogin(DEMO_USER.password, DEMO_USER.email);
    const res = await authApi.login({ email: DEMO_USER.email, authSecret });
    expect(isLoginResponse(res)).toBe(true);
  });

  it('register -> login round trip works with the same password', async () => {
    const email = 'round@trip.co';
    const reg = await authApi.register(await registerBody(email, 'my-long-password-1'));
    const { authSecret } = await prepareLogin('my-long-password-1', email);
    const res = await authApi.login({ email, authSecret });
    expect(res.userId).toBe(reg.userId);
  });

  it('wrong password and unknown user give the same invalid_credentials error', async () => {
    const bad = await prepareLogin('wrong', DEMO_USER.email);
    await expect(authApi.login({ email: DEMO_USER.email, authSecret: bad.authSecret })).rejects.toMatchObject({ code: 'invalid_credentials' });
    const ghost = await prepareLogin('whatever', 'ghost@nowhere.co');
    await expect(authApi.login({ email: 'ghost@nowhere.co', authSecret: ghost.authSecret })).rejects.toMatchObject({ code: 'invalid_credentials' });
  });

  it('duplicate email gives email_taken', async () => {
    await authApi.register(await registerBody('dupe@x.co'));
    await expect(authApi.register(await registerBody('DUPE@x.co'))).rejects.toMatchObject({ code: 'email_taken' });
  });

  it('rejects a request that drifts from the contract', async () => {
    const body = await registerBody('drift@x.co');
    delete body.kdfSalt;
    await expect(authApi.register(body)).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('getAuthParams returns a salt for known and unknown emails alike', async () => {
    const known = await authApi.getAuthParams(DEMO_USER.email);
    const ghost = await authApi.getAuthParams('ghost@nowhere.co');
    expect(typeof known.kdfSalt).toBe('string');
    expect(typeof ghost.kdfSalt).toBe('string');
    expect(Number.isInteger(known.kdfIterations)).toBe(true);
  });

  it('never sends the password anywhere in the payload', async () => {
    const body = await registerBody('pw@x.co', 'super-secret-password-xyz');
    expect(JSON.stringify(body)).not.toContain('super-secret-password-xyz');
    expect(body).not.toHaveProperty('password');
  });
});
