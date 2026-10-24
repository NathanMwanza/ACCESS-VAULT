import { useAuth } from '../context/AuthContext.jsx';
import { USING_MOCK } from '../services/authApi.js';
import FolderExplorer from '../components/explorer/FolderExplorer.jsx';
import Logo from '../components/Logo.jsx';
import Alert from '../components/Alert.jsx';
import Button from '../components/Button.jsx';

/** Stand-in for the file explorer (Phase 3). Proves the login worked and the session is held. */
export default function VaultPlaceholderPage() {
  const { session, logout } = useAuth();

  return (
    <div className="vault">
      <header className="vault__bar">
        <div className="vault__brand"><Logo /></div>
        <div className="vault__user">
          <span>{session.displayName ?? session.email}</span>
          <Button variant="ghost" onClick={logout}>Sign out</Button>
        </div>
      </header>

      <main className="vault__main">
        {session.justRegistered && (
          <Alert variant="success">Your account is ready. You're signed in.</Alert>
        )}
        {USING_MOCK && (
          <Alert variant="info" title="Mock mode">
            You are signed in against the built-in mock, not the real backend. Set
            VITE_USE_MOCK=false in .env.local to use Supabase.
          </Alert>
        )}

        <FolderExplorer />
      </main>
    </div>
  );
}
