import { useCallback, useEffect, useState } from 'react';
import Alert from '../Alert.jsx';
import Button from '../Button.jsx';
import TextField from '../TextField.jsx';
import { listShares, lookupRecipient, revokeShare, shareFolder } from '../../services/shareFlow.js';

/**
 * Share one folder read-only, and see/revoke who already has it.
 * Step 1: find the person by email and show their key fingerprint. Step 2: confirm and share.
 * (The fingerprint lets the two people check out of band that the server handed over the right public key.)
 */
export default function SharePanel({ folder, onClose }) {
  const [email, setEmail] = useState('');
  const [found, setFound] = useState(null); // { userId, name, publicKey, fingerprint }
  const [shares, setShares] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [days, setDays] = useState(''); // '' = no expiry

  const refresh = useCallback(async () => {
    try {
      setShares(await listShares(folder.id));
    } catch (err) {
      setError(err.message);
      setShares([]);
    }
  }, [folder.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function run(action) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const onFind = (event) => {
    event.preventDefault();
    run(async () => setFound(await lookupRecipient(email)));
  };

  const onShare = () =>
    run(async () => {
      const expiresAt = days ? new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000) : null;
      await shareFolder(folder.id, found, { expiresAt });
      setNotice(`Shared "${folder.name}" with ${found.name}. They can view it, not change it.`);
      setDays('');
      setFound(null);
      setEmail('');
      await refresh();
    });

  const onRevoke = (share) =>
    run(async () => {
      if (!window.confirm(`Stop sharing "${folder.name}" with ${share.name}?`)) return;
      await revokeShare(share.shareId);
      setNotice(`${share.name} can no longer open this folder.`);
      await refresh();
    });

  return (
    <section className="share" aria-labelledby="share-title">
      <div className="share__head">
        <h2 id="share-title">Share “{folder.name}”</h2>
        <button type="button" className="explorer__folder" onClick={onClose}>Close</button>
      </div>
      <p className="share__hint">People you share with can view and download everything in this folder, including subfolders. They cannot change anything.</p>

      {error && <Alert variant="error">{error}</Alert>}
      {notice && <Alert variant="success">{notice}</Alert>}

      {!found ? (
        <form className="explorer__new" onSubmit={onFind} noValidate>
          <TextField label="Their email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" />
          <Button type="submit" loading={busy}>Find</Button>
        </form>
      ) : (
        <div className="share__confirm">
          <p><strong>{found.name}</strong> — key fingerprint:</p>
          <p><code aria-label="Key fingerprint">{found.fingerprint}</code></p>
          <p className="share__hint">Ask them to confirm this matches the fingerprint in their account before you share.</p>
          <div className="field">
            <label htmlFor="share-expiry">Access ends</label>
            <select id="share-expiry" value={days} onChange={(e) => setDays(e.target.value)}>
              <option value="">Never (until you revoke it)</option>
              <option value="1">After 1 day</option>
              <option value="7">After 7 days</option>
              <option value="30">After 30 days</option>
            </select>
          </div>
          <div className="explorer__new">
            <Button onClick={onShare} loading={busy}>Share read-only</Button>
            <Button variant="ghost" onClick={() => setFound(null)} disabled={busy}>Cancel</Button>
          </div>
        </div>
      )}

      <h3 className="share__sub">Shared with</h3>
      {shares === null ? (
        <p className="explorer__status" role="status">Loading…</p>
      ) : shares.length === 0 ? (
        <p className="explorer__empty">Nobody yet.</p>
      ) : (
        <ul className="explorer__list" aria-label="Shared with">
          {shares.map((s) => (
            <li key={s.shareId}>
              <span>{s.name} <small>{s.email}{s.expiresAt ? ` · until ${new Date(s.expiresAt).toLocaleDateString()}` : ''}</small></span>
              <button type="button" className="explorer__folder" disabled={busy} onClick={() => onRevoke(s)}>Revoke</button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
