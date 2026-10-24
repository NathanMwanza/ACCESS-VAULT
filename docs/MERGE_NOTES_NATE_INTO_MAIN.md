# Merge notes: Nate's authFlow wired into the app

Base: the `Nate` branch. What was broken and what changed:

| Problem | Fix |
|---|---|
| `AuthContext` imported `initAuthFlow` (does not exist) and `createFolder/createGrant/getVault` from `supabaseAuthApi.js` (not there) | `AuthContext` now calls `authFlow.configure({ backend: authApi })` and `authFlow.register/login/logout` |
| `register` called with `(email, password, {displayName})`; authFlow takes `(email, displayName, password)` | argument order fixed |
| `authApi.js` deleted but still imported by pages and tests | restored; now returns the full backend (auth + vault calls) |
| Vault calls did not exist on the backend | `src/services/supabaseVaultApi.js` + mock equivalents in `mockAuthApi.js` |
| DB could not store an encrypted folder name or a key grant | `supabase/migrations/002_vault_folders_and_grants.sql` (**run it in Supabase**) |
| Mock used fake crypto, so mock mode could not run the real flow | mock stores real keys, seeds the demo user with real keys, `mockCrypto.js` removed |
| `npm install` failed (`@vitejs/plugin-react@4` does not support Vite 8) | plugin-react `^6.1.2`; lockfile regenerated |
| Tests: 2 expected `'unknown'`, the code is `'unknown_error'` | tests corrected |
| Merge-conflict markers in `README.md` / `.gitignore` (main) | resolved |
| `env.download` (real project URL + key) and `src - Shortcut.lnk` in the repo | removed. Keep `.env.local` out of git; consider rotating the publishable key |

Behaviour notes
- If saving the vault folder fails during registration, `register()` still succeeds (the account exists) and
  `login()` creates the vault next time. `session.vaultFolderKey` is `null` until then; Phase 3 should call
  `loadVault()` before using it.
- The "Backend check" panel still writes plaintext folder names (`folders.name`). Those rows are ignored by
  `getVault()`. Remove the panel when the explorer lands, since plaintext names break the zero-trust claim.
- `docs/OPEN_QUESTIONS.md` #5 is settled in code: raw ECDH P-256 (65 bytes), not RSA-OAEP. Update Chapter 4.

Checks: `npm test` (38 tests), `npm run test:flow` (22), `npm run test:crypto`, `npm run build`.

---

# Phase 3a: real encrypted folders (new branch)

- **Removed** the Backend check panel (`BackendCheck.jsx`, `supabaseFoldersApi.js`, its CSS).
- **`src/services/folderFlow.js`**: `listFolders()` and `createSubfolder(name, parentId)`. A subfolder gets its own random
  AES key, wrapped under its parent's key (`folders.wrapped_key`); its name is encrypted with its own key
  (`folders.name_enc`). Holding the vault key opens the whole tree, and the server only ever sees ciphertext.
- **Backend**: `listFolders()` added to `supabaseVaultApi.js` and the mock (owner's encrypted folders only).
- **UI**: `src/components/explorer/FolderExplorer.jsx` (breadcrumbs, create, open) replaces the empty placeholder.
- **Migration 003** (`supabase/migrations/003_folder_integrity.sql`, **applied to the live project**):
  - check constraint: a folder must have `name_enc` and must not have `name`/`path`;
  - insert/update policies: `parent_id` must be null or one of your own folders.
  `policies.sql` and `schema_reference.sql` updated to match.
- **Tests**: 54 in `npm test` (new: `folderFlow.test.js`, explorer UI flows, `listFolders` mapping).
- Not done yet: rename/move/delete folders, files, sharing (grants to other users via `get_user_public_key`).

---

# Phase 3b: encrypted files

- **Migration 004** (`supabase/migrations/004_encrypted_files.sql`, **applied to the live project**):
  - `files.name_enc` added; `files.name`/`type` must stay empty (same zero-trust guard as folders);
  - `file_chunks`: unique `(file_id, chunk_index)` and a size cap matching the bucket (5,243,904 bytes);
  - **fixed the Storage policies on the `chunks` bucket.** They called `storage.foldername(f.name)`, and inside that
    sub-query `name` is `files.name`, not the object path, so even the owner's own upload was denied (tested before and after).
    They now use `objects.name`. Policies are limited to signed-in users; chunks can only be written while the file is `uploading`.
- **`fileFlow.js`**: `uploadFile`, `listFiles`, `downloadFile`, `deleteFile`.
  Per-file random key wrapped under the folder key; name encrypted with the file key; 5 MiB chunks, nonce = baseNonce||index,
  AAD = fileId||index||isLast; a failed upload is cleaned up; a chunk that fails authentication aborts the download.
- **`supabaseFilesApi.js`** + mock equivalents. Object path: `files/<fileId>/<chunkIndex>` in the private `chunks` bucket.
- **UI**: upload, download, delete in `FolderExplorer`.
- **Tests (76 total)**: round trip across chunks, empty and exact-multiple files, nothing readable reaches the backend,
  recovery after re-login, and a dishonest server that flips bits, swaps/reorders chunks, substitutes another file's chunk,
  drops the last chunk, or deletes a chunk, all detected.
- Not done: sharing (storage read policy is owner-only on purpose until grants exist), file rename/move, resumable uploads
  (an interrupted upload is cleaned up in the browser; a closed tab can leave an `uploading` row, which a cleanup job could purge),
  files over 50 MB, and the two function lockdowns from the security check.

---

# Phase 3c: sharing folders (read-only) and revoking

Sharing was built twice by accident (two sessions). This is the merged result: the earlier build as the base,
plus expiry and the completed-file rule from the second.

- **Migration 005** (`supabase/migrations/005_sharing.sql`, **run it in the Supabase SQL editor**; it was not applied automatically):
  - a share on a folder covers every subfolder and file under it (`has_folder_access`, walks up the parents, depth-limited);
  - non-owners can read a file only when its upload is `complete`; chunk reads follow file visibility;
  - **clients can no longer insert, update or delete `public.shares` directly.** The old UPDATE rule let a share's owner
    re-point it at another person's folder. Shares are now written only by `share_resource` / `revoke_share`;
  - `share_resource` saves the share and the recipient's key grant in one transaction, takes an optional expiry,
    refuses the vault root, yourself, duplicates and folders you do not own;
  - `revoke_share` sets `revoked_at` and deletes the recipient's key grant;
  - one active share per (folder, person); the duplicate `key_envelopes_unique_grant` index is dropped;
  - advisor fixes: `handle_new_user` is no longer callable through the API; `get_user_public_key` needs sign-in.
- **App**: `shareFlow.js` (lookup + key fingerprint, share with optional expiry, list, revoke, open shared tree),
  `supabaseSharingApi.js` (rebuilt to match the migration), `SharePanel.jsx` (find, check fingerprint, choose expiry, revoke),
  `SharedWithMe.jsx`. The recipient unwraps the folder key with their private key; subfolder and file keys then unwrap in the usual chain.
- **Revoking** cuts server access at once and deletes the key grant. Someone who already downloaded and decrypted a file keeps that copy,
  and the folder key is not rotated. Re-keying a folder (new key, re-wrap subfolders, re-encrypt files) is not built. Say so in Chapter 4.
- **Trust**: the server supplies the recipient's public key, so the UI shows its fingerprint to compare out of band.
- **Tests**: 100 in `npm test` (sharing round trips, third-party access, revoke, re-share, expiry, unfinished uploads, Supabase API mapping, UI flow).
