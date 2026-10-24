import { useCallback, useEffect, useMemo, useState } from 'react';
import Alert from '../Alert.jsx';
import Button from '../Button.jsx';
import TextField from '../TextField.jsx';
import { FOLDER_NAME_MAX, createSubfolder, getVaultFolderId, listFolders } from '../../services/folderFlow.js';
import { MAX_FILE_BYTES, deleteFile, downloadFile, listFiles, uploadFile } from '../../services/fileFlow.js';

const formatSize = (n) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

/** Hands a decrypted Blob to the browser as a normal download. */
function saveBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

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
  const [files, setFiles] = useState([]);
  const [progress, setProgress] = useState(null); // { name, done, total } while uploading
  const [workingFileId, setWorkingFileId] = useState(null);

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

  // Files of the open folder. Loaded whenever the folder changes.
  useEffect(() => {
    if (!currentId || folders === null) return undefined;
    let cancelled = false;
    listFiles(currentId)
      .then((list) => !cancelled && setFiles(list))
      .catch((err) => !cancelled && setError(err.message));
    return () => {
      cancelled = true;
    };
  }, [currentId, folders]);

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

  async function onPickFiles(event) {
    const picked = Array.from(event.target.files ?? []);
    event.target.value = ''; // allow picking the same file again
    setError(null);
    for (const file of picked) {
      if (file.size > MAX_FILE_BYTES) {
        setError(`${file.name} is larger than ${Math.floor(MAX_FILE_BYTES / 1024 / 1024)} MB.`);
        continue;
      }
      try {
        setProgress({ name: file.name, done: 0, total: 1 });
        const saved = await uploadFile(file, currentId, {
          onProgress: (done, total) => setProgress({ name: file.name, done, total }),
        });
        setFiles((cur) => [...cur, { ...saved, createdAt: new Date().toISOString() }]);
      } catch (err) {
        setError(err.message);
      }
    }
    setProgress(null);
  }

  async function onDownload(file) {
    setWorkingFileId(file.id);
    setError(null);
    try {
      const { name, blob } = await downloadFile(file.id, currentId);
      saveBlob(name, blob);
    } catch (err) {
      setError(err.message);
    } finally {
      setWorkingFileId(null);
    }
  }

  async function onDelete(file) {
    if (!window.confirm(`Delete ${file.name}? This cannot be undone.`)) return;
    setWorkingFileId(file.id);
    setError(null);
    try {
      await deleteFile(file.id);
      setFiles((cur) => cur.filter((f) => f.id !== file.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setWorkingFileId(null);
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

      {children.length === 0 && files.length === 0 ? (
        <p className="explorer__empty">No folders here yet. Names are encrypted before they leave your device.</p>
      ) : null}

      {children.length > 0 && (
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

      <div className="explorer__upload">
        <label className="btn btn--primary explorer__pick">
          <input type="file" multiple hidden onChange={onPickFiles} disabled={progress !== null} aria-label="Upload files" />
          <span>Upload files</span>
        </label>
        {progress && (
          <span role="status" className="explorer__progress">
            Encrypting and uploading {progress.name}… {progress.done}/{progress.total}
          </span>
        )}
      </div>

      {files.length > 0 && (
        <ul className="explorer__list explorer__files" aria-label="Files">
          {files.map((f) => (
            <li key={f.id}>
              <span className="explorer__file">
                <span aria-hidden="true">🔒</span> {f.name} <small>{formatSize(f.size)}</small>
              </span>
              <span className="explorer__actions">
                <button type="button" className="explorer__folder" disabled={workingFileId === f.id} onClick={() => onDownload(f)}>
                  Download
                </button>
                <button type="button" className="explorer__folder" disabled={workingFileId === f.id} onClick={() => onDelete(f)}>
                  Delete
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
