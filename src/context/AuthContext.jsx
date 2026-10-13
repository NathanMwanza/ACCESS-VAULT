import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { authApi } from '../services/authApi.js';
import { prepareLogin, prepareRegistration } from '../services/cryptoBridge.js';

// Session lives in React state ONLY (Phase 2 rule: "keep the session in memory only").
// Nothing is written to localStorage, sessionStorage or cookies, so a refresh or
// closing the tab logs the user out and drops everything.

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  // One-shot message shown by the next screen (e.g. "You have been signed out"). Memory only.
  const [notice, setNotice] = useState(null);

  const register = useCallback(async ({ displayName, email, password }) => {
    const cleanEmail = email.trim();
    const cleanName = displayName.trim();
    const cryptoFields = await prepareRegistration(password, cleanEmail);
    const { userId, sessionToken } = await authApi.register({
      email: cleanEmail,
      displayName: cleanName,
      ...cryptoFields,
    });
    setNotice(null);
    setSession({
      userId,
      sessionToken,
      email: cleanEmail,
      displayName: cleanName,
      justRegistered: true,
      // Key material for the later phases is held here once Nathan's module returns it.
    });
  }, []);

  const login = useCallback(async ({ email, password }) => {
    const cleanEmail = email.trim();
    const { authSecret } = await prepareLogin(password, cleanEmail);
    const { userId, sessionToken, kdfSalt, wrappedPrivateKey } = await authApi.login({
      email: cleanEmail,
      authSecret,
    });
    setNotice(null);
    setSession({
      userId,
      sessionToken,
      email: cleanEmail,
      displayName: null, // login response carries no name (per the contract)
      kdfSalt,
      wrappedPrivateKey,
    });
  }, []);

  const logout = useCallback(() => {
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
