import { useCallback, useState } from 'react';
import Alert from './Alert.jsx';
import Button from './Button.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { createFolder, listFolders } from '../services/supabaseFoldersApi.js';

/**
 * Temporary panel (real backend only). Creates and lists folders so you can see that the
 * signed-in session passes Row Level Security from the React app. Replaced by the file
 * explorer in Phase 3.
 */
export default function BackendCheck() {
  const { session } = useAuth();
  const [folders, setFolders] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const run = useCallback(async (action) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      setFolders(await listFolders());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }, []);

  const onCreate = () => run(() => createFolder(session.userId, `Test folder ${new Date().toLocaleTimeString()}`));
  const onLoad = () => run(async () => {});

  return (
    <section className="backend-check" aria-labelledby="backend-check-title">
      <h2 id="backend-check-title">Backend check</h2>
      <p>Create a folder in your Supabase database, then load the folders your account can see.</p>

      <div className="backend-check__actions">
        <Button onClick={onCreate} loading={busy}>Create test folder</Button>
        <Button variant="ghost" onClick={onLoad} disabled={busy}>Load my folders</Button>
      </div>

      {error && <Alert variant="error">{error}</Alert>}

      {folders && (
        folders.length === 0 ? (
          <p className="backend-check__empty">No folders yet.</p>
        ) : (
          <ul className="backend-check__list">
            {folders.map((f) => (
              <li key={f.folder_id}><span>{f.name}</span><code>{f.path}</code></li>
            ))}
          </ul>
        )
      )}
    </section>
  );
}
