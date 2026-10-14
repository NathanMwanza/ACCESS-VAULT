import { beforeEach, describe, expect, it, vi } from 'vitest';

// A fake Supabase client: we test OUR code (what it sends, how it maps errors), not Supabase.
const fake = { auth: {}, rpc: vi.fn(), from: vi.fn() };
vi.mock('../src/services/supabaseClient.js', () => ({ getSupabase: () => fake }));

const { getAuthParams, login, register } = await import('../src/services/supabaseAuthApi.js');

const SESSION = { access_token: 'jwt-123', user: { id: '11111111-1111-1111-1111-111111111111' } };
const PAYLOAD = {
  email: 'a@b.co',
  displayName: 'Ada',
  authSecret: 'AUTHSECRET_BASE64==',
  kdfSalt: 'SALT',
  kdfIterations: 600000,
  publicKey: 'PUB',
  wrappedPrivateKey: 'WRAPPED',
};

beforeEach(() => {
  vi.restoreAllMocks();
  fake.auth.signUp = vi.fn();
  fake.auth.signInWithPassword = vi.fn();
  fake.auth.signOut = vi.fn();
  fake.rpc = vi.fn();
  fake.from = vi.fn();
});

describe('supabaseAuthApi.register', () => {
  it('sends authSecret as the password and the crypto fields as metadata', async () => {
    fake.auth.signUp.mockResolvedValue({ data: { user: { identities: [{}] }, session: SESSION }, error: null });
    const res = await register(PAYLOAD);

    const arg = fake.auth.signUp.mock.calls[0][0];
    expect(arg.password).toBe('AUTHSECRET_BASE64==');
    expect(arg.options.data).toEqual({
      name: 'Ada',
      kdf_salt: 'SALT',
      kdf_iterations: 600000,
      public_key: 'PUB',
      wrapped_private_key: 'WRAPPED',
    });
    expect(res).toEqual({ userId: SESSION.user.id, sessionToken: 'jwt-123' });
  });

  it('maps an existing email to email_taken', async () => {
    fake.auth.signUp.mockResolvedValue({ data: {}, error: { code: 'user_already_exists', message: 'User already registered', status: 422 } });
    await expect(register(PAYLOAD)).rejects.toMatchObject({ code: 'email_taken' });
  });

  it('treats a user with no identities (confirmation on) as email_taken', async () => {
    fake.auth.signUp.mockResolvedValue({ data: { user: { identities: [] }, session: null }, error: null });
    await expect(register(PAYLOAD)).rejects.toMatchObject({ code: 'email_taken' });
  });

  it('reports email_not_confirmed when no session can be opened yet', async () => {
    fake.auth.signUp.mockResolvedValue({ data: { user: { identities: [{}] }, session: null }, error: null });
    fake.auth.signInWithPassword.mockResolvedValue({ data: {}, error: { code: 'email_not_confirmed', message: 'Email not confirmed' } });
    await expect(register(PAYLOAD)).rejects.toMatchObject({ code: 'email_not_confirmed' });
  });

  it('keeps raw database errors out of the UI message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    fake.auth.signUp.mockResolvedValue({ data: {}, error: { message: 'Database error saving new user', status: 500 } });
    await expect(register(PAYLOAD)).rejects.toMatchObject({ code: 'unknown', message: expect.not.stringContaining('Database') });
  });
});

describe('supabaseAuthApi.login', () => {
  it('signs in with authSecret and returns the stored salt and wrapped key', async () => {
    fake.auth.signInWithPassword.mockResolvedValue({ data: { session: SESSION }, error: null });
    const single = vi.fn().mockResolvedValue({ data: { name: 'Ada', salt: 'SALT', wrapped_private_key: 'WRAPPED' }, error: null });
    const eq = vi.fn(() => ({ single }));
    fake.from.mockReturnValue({ select: vi.fn(() => ({ eq })) });

    const res = await login({ email: 'a@b.co', authSecret: 'AUTHSECRET_BASE64==' });

    expect(fake.auth.signInWithPassword).toHaveBeenCalledWith({ email: 'a@b.co', password: 'AUTHSECRET_BASE64==' });
    expect(fake.from).toHaveBeenCalledWith('users');
    expect(eq).toHaveBeenCalledWith('user_id', SESSION.user.id);
    expect(res).toMatchObject({ userId: SESSION.user.id, sessionToken: 'jwt-123', kdfSalt: 'SALT', wrappedPrivateKey: 'WRAPPED', displayName: 'Ada' });
  });

  it('maps invalid_credentials to the generic message', async () => {
    fake.auth.signInWithPassword.mockResolvedValue({ data: {}, error: { code: 'invalid_credentials', message: 'Invalid login credentials', status: 400 } });
    await expect(login({ email: 'a@b.co', authSecret: 'x' })).rejects.toMatchObject({ code: 'invalid_credentials' });
  });
});

describe('supabaseAuthApi.getAuthParams', () => {
  it('calls the get_auth_params function and maps the row', async () => {
    fake.rpc.mockResolvedValue({ data: [{ kdf_salt: 'SALT', kdf_iterations: 600000 }], error: null });
    expect(await getAuthParams('a@b.co')).toEqual({ kdfSalt: 'SALT', kdfIterations: 600000 });
    expect(fake.rpc).toHaveBeenCalledWith('get_auth_params', { p_email: 'a@b.co' });
  });

  it('rejects a malformed response', async () => {
    fake.rpc.mockResolvedValue({ data: [], error: null });
    await expect(getAuthParams('a@b.co')).rejects.toMatchObject({ code: 'unknown' });
  });
});
