import { useCallback, useEffect, useMemo, useState } from 'react';
import Alert from '../Alert.jsx';
import { downloadFile, listFiles } from '../../services/fileFlow.js';
import { listSharedWithMe, openSharedFolder } from '../../services/shareFlow.js';
import { formatSize, saveBlob } from '../../utils/format.js';

/** Folders other people shared with me: browse and download only. Names and keys are handled in shareFlow.js. */
export default function SharedWithMe() {
  const [shares, setShares] = useState(null);
  const [open, setOpen] = useState(null); // { share, tree }
  const [currentId, setCurrentId] = useState(null);
  const [files, setFiles] = useState([]);
  const [error, setError] = useState(null);
  const [workingFileId, setWorkingFileId] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setShares(await listSharedWithMe());
    } catch (err) {
      setError(err.message);
      setShares([]);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!currentId) return undefined;
    let cancelled = false;
    listFiles(currentId)
      .then((list) => !cancelled && setFiles(list))
      .catch((err) => !cancelled && setError(err.message));
    return () => {
      cancelled = true;
    };
  }, [currentId]);

  async function onOpen(share) {
    setError(null);
    try {
      const tree = await openSharedFolder(share.folderId);
      setOpen({ share, tree });
      setCurrentId(share.folderId);
      setFiles([]);
    } catch (err) {
      setError(err.message);
      load();
    }
  }

  function onBack() {
    setOpen(null);
    setCurrentId(null);
    setFiles([]);
    load();
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

  const byId = useMemo(() => new Map((open?.tree ?? []).map((f) => [f.id, f])), [open]);
  const children = useMemo(
    () => (open?.tree ?? []).filter((f) => f.parentId === currentId).sort((a, b) => a.name.localeCompare(b.name)),
    [open, currentId],
  );
  const trail = useMemo(() => {
    const out = [];
    for (let f = byId.get(currentId); f; f = byId.get(f.parentId)) out.unshift(f);
    return out;
  }, [byId, currentId]);

  if (shares === null) return <p className="explorer__status" role="status">Loading shared folders…</p>;

  if (!open) {
    return (
      <section className="explorer" aria-labelledby="shared-title">
        <h1 id="shared-title" className="explorer__title">Shared with me</h1>
        {error && <Alert variant="error">{error}</Alert>}
        {shares.length === 0 ? (
          <p className="explorer__empty">Nothing has been shared with you yet.</p>
        ) : (
          <ul className="explorer__list" aria-label="Shared folders">
            {shares.map((s) => (
              <li key={s.shareId}>
                <button type="button" className="explorer__folder" onClick={() => onOpen(s)}>
                  <span aria-hidden="true">📁</span> {s.name}
                </button>
                <small>from {s.ownerName}</small>
              </li>
            ))}
          </ul>
        )}
      </section>
    );
  }

  return (
    <section className="explorer" aria-labelledby="shared-title">
      <h1 id="shared-title" className="explorer__title">Shared with me</h1>
      <nav className="explorer__crumbs" aria-label="Folder path">
        <button type="button" className="explorer__crumb" onClick={onBack}>All shared</button>
        {trail.map((f) => (
          <span key={f.id}>
            <span aria-hidden="true"> / </span>
            {f.id === currentId ? (
              <span aria-current="page">{f.name}</span>
            ) : (
              <button type="button" className="explorer__crumb" onClick={() => setCurrentId(f.id)}>{f.name}</button>
            )}
          </span>
        ))}
      </nav>
      <p className="share__hint">Shared by {open.share.ownerName}. You can view and download, not change.</p>
      {error && <Alert variant="error">{error}</Alert>}

      {children.length > 0 && (
        <ul className="explorer__list" aria-label="Folders">
          {children.map((f) => (
            <li key={f.id}>
              <button type="button" className="explorer__folder" onClick={() => setCurrentId(f.id)}>
                <span aria-hidden="true">📁</span> {f.name}
              </button>
            </li>
          ))}
        </ul>
      )}

      {files.length > 0 && (
        <ul className="explorer__list explorer__files" aria-label="Files">
          {files.map((f) => (
            <li key={f.id}>
              <span className="explorer__file"><span aria-hidden="true">🔒</span> {f.name} <small>{formatSize(f.size)}</small></span>
              <button type="button" className="explorer__folder" disabled={workingFileId === f.id} onClick={() => onDownload(f)}>Download</button>
            </li>
          ))}
        </ul>
      )}
      {children.length === 0 && files.length === 0 && <p className="explorer__empty">This folder is empty.</p>}
    </section>
  );
}
