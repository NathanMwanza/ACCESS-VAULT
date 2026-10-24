import { useCallback, useEffect, useMemo, useState } from 'react';
import Alert from '../Alert.jsx';
import Button from '../Button.jsx';
import TextField from '../TextField.jsx';
import { FOLDER_NAME_MAX, createSubfolder, getVaultFolderId, listFolders } from '../../services/folderFlow.js';

/**
 * Folder browser for the encrypted vault. Names are decrypted in the browser by folderFlow.js;
 * this component only ever sees plain names and ids, never keys.
 */
export default function FolderExplorer() {
  const [folders, setFolders] = useState(null); // null = loading
  const [vaultId, setVaultId] = useState(null);
  const [currentId, setCurrentId] = useState(null);
  const [name, setName] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [id, all] = await Promise.all([getVaultFolderId(), listFolders()]);
      setVaultId(id);
      setCurrentId((cur) => cur ?? id);
      setFolders(all);
    } catch (err) {
      setError(err.message);
      setFolders((cur) => cur ?? []);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const byId = useMemo(() => new Map((folders ?? []).map((f) => [f.id, f])), [folders]);
  const children = useMemo(
    () => (folders ?? []).filter((f) => f.parentId === currentId).sort((a, b) => a.name.localeCompare(b.name)),
    [folders, currentId],
  );
  const trail = useMemo(() => {
    const out = [];
    for (let f = byId.get(currentId); f; f = byId.get(f.parentId)) out.unshift(f);
    return out;
  }, [byId, currentId]);

  async function onCreate(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await createSubfolder(name, currentId);
      setFolders((cur) => [...(cur ?? []), created]);
      setName('');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (folders === null) return <p className="explorer__status" role="status">Unlocking your vault…</p>;

  return (
    <section className="explorer" aria-labelledby="explorer-title">
      <h1 id="explorer-title" className="explorer__title">Your vault</h1>

      <nav className="explorer__crumbs" aria-label="Folder path">
        {trail.map((f, i) => (
          <span key={f.id}>
            {i > 0 && <span aria-hidden="true"> / </span>}
            {f.id === currentId ? (
              <span aria-current="page">{f.id === vaultId ? 'Vault' : f.name}</span>
            ) : (
              <button type="button" className="explorer__crumb" onClick={() => setCurrentId(f.id)}>
                {f.id === vaultId ? 'Vault' : f.name}
              </button>
            )}
          </span>
        ))}
      </nav>

      {error && <Alert variant="error">{error}</Alert>}

      <form className="explorer__new" onSubmit={onCreate} noValidate>
        <TextField
          label="New folder name"
          value={name}
          maxLength={FOLDER_NAME_MAX}
          onChange={(e) => setName(e.target.value)}
          autoComplete="off"
        />
        <Button type="submit" loading={busy}>Create folder</Button>
      </form>

      {children.length === 0 ? (
        <p className="explorer__empty">No folders here yet. Names are encrypted before they leave your device.</p>
      ) : (
        <ul className="explorer__list">
          {children.map((f) => (
            <li key={f.id}>
              <button type="button" className="explorer__folder" onClick={() => setCurrentId(f.id)}>
                <span aria-hidden="true">📁</span> {f.name}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
