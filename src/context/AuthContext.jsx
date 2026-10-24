import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { authApi } from '../services/authApi.js';
import * as authFlow from '../services/authFlow.js';

// authFlow.js is the crypto layer (keys, wrapping, vault folder). It talks to whichever backend
// authApi.js picked (mock or Supabase). Pages and this context never touch keys or the password
// beyond handing the password to authFlow.
authFlow.configure({ backend: authApi });

// Session lives in React state ONLY (Phase 2 rule: "keep the session in memory only").
// Nothing is written to localStorage, sessionStorage or cookies, so a refresh or
// closing the tab logs the user out and drops everything. The unwrapped private key and vault
// key live in authFlow's own in-memory session, which logout() clears first.

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  // One-shot message shown by the next screen (e.g. "You have been signed out"). Memory only.
  const [notice, setNotice] = useState(null);

  const register = useCallback(async ({ displayName, email, password }) => {
    const cleanEmail = email.trim();
    const cleanName = displayName.trim();
    const { userId } = await authFlow.register(cleanEmail, cleanName, password);
    setNotice(null);
    setSession({ userId, email: cleanEmail, displayName: cleanName, justRegistered: true });
  }, []);

  const login = useCallback(async ({ email, password }) => {
    const cleanEmail = email.trim();
    const { userId, displayName } = await authFlow.login(cleanEmail, password);
    setNotice(null);
    setSession({ userId, email: cleanEmail, displayName: displayName ?? null });
  }, []);

  const logout = useCallback(async () => {
    await authFlow.logout(); // drops keys first, then ends the backend session; never throws
    setSession(null);
    setNotice('signed_out');
  }, []);

  const value = useMemo(
    () => ({ session, notice, isAuthenticated: session !== null, register, login, logout }),
    [session, notice, register, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
