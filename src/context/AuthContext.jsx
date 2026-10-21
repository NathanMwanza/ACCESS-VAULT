import { createFolder, createGrant, getVault } from '../services/supabaseAuthApi.js';
import { initAuthFlow } from '../services/authFlow.js';

// Initialize authFlow with backend methods
const auth = initAuthFlow({
  createFolder,
  createGrant,
  getVault
});


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

    // Replaces prepareRegistration + authApi.register with client-side zero-trust authFlow
    const sessionData = await auth.register(cleanEmail, password, { displayName: cleanName });

    setNotice(null);
    setSession({
      ...sessionData,
      email: cleanEmail,
      displayName: cleanName,
      justRegistered: true,
    });
    return sessionData;
  }, []);

  const login = useCallback(async ({ email, password }) => {
    const cleanEmail = email.trim();

    // Replaces getAuthParams + prepareLogin + authApi.login with authFlow
    const sessionData = await auth.login(cleanEmail, password);

    setNotice(null);
    setSession({
      ...sessionData,
      email: cleanEmail,
    });
    return sessionData;
  }, []);

  const logout = useCallback(async () => {
    // End session using authFlow and clear local state
    await auth.logout().catch(() => {});
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