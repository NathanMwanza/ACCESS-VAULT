// Sharing calls used by shareFlow.js (same function names and shapes as the mock in mock/mockAuthApi.js).
// The server stores who has access plus the folder key wrapped to the recipient (it cannot read it).
// Shares are written ONLY through the database functions in migration 005 (clients cannot insert,
// update or delete rows in public.shares directly), so every share is checked for ownership.

import { ApiError } from "./apiClient.js";
import { ERROR_CODES } from "./contract.js";
import { getSupabase } from "./supabaseClient.js";

const FRIENDLY = {
  only_folders_can_be_shared: "Only folders can be shared.",
  only_read_only_sharing: "Sharing is read-only.",
  cannot_share_with_yourself: "You cannot share with yourself.",
  cannot_share_vault_root:
    "Your whole vault cannot be shared. Share a folder inside it.",
  recipient_not_found: "No Access Vault account was found for that email.",
  not_your_folder: "You can only share folders you own.",
  already_shared: "This folder is already shared with that person.",
  share_not_found: "That share no longer exists.",
  expiry_in_past: "The expiry time must be in the future.",
  missing_key: "Something went wrong. Please try again.",
};

function fail(error) {
  const message = String(error?.message ?? "");
  for (const [token, text] of Object.entries(FRIENDLY)) {
    if (message.includes(token))
      return new ApiError(ERROR_CODES.INVALID_REQUEST, text, 400);
  }
  // A race between two "share" clicks hits the unique index instead of the friendly check.
  if (error?.code === "23505")
    return new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      FRIENDLY.already_shared,
      409,
    );
  console.error("[supabase]", error);
  const network =
    error?.name === "AuthRetryableFetchError" ||
    /failed to fetch|network/i.test(message);
  return network
    ? new ApiError(
        ERROR_CODES.NETWORK_ERROR,
        "Could not reach the server. Check your connection and try again.",
      )
    : new ApiError(
        ERROR_CODES.UNKNOWN,
        "Something went wrong. Please try again.",
        error?.status ?? 0,
      );
}

async function currentUserId() {
  const { data, error } = await getSupabase().auth.getSession();
  const id = data?.session?.user?.id;
  if (error || !id)
    throw new ApiError(
      ERROR_CODES.INVALID_CREDENTIALS,
      "Please sign in again.",
      401,
    );
  return id;
}

/** Another user's id, name and public key by email, or null (also null for yourself). */
export async function findShareTarget(email) {
  const { data, error } = await getSupabase().rpc("find_user_for_share", {
    p_email: email,
  });
  if (error) throw fail(error);
  const row = Array.isArray(data) ? data[0] : data;
  return row
    ? { userId: row.user_id, publicKey: row.public_key, name: row.name }
    : null;
}

/** Saves the share and the recipient's key grant together. expiresAt: ISO string or null. Returns { shareId }. */
export async function shareResource({
  resourceType,
  resourceId,
  recipientId,
  level = "VIEWER",
  wrappedKey,
  ephemeralPublicKey,
  expiresAt = null,
}) {
  const { data, error } = await getSupabase().rpc("share_resource", {
    p_resource_type: String(resourceType).toLowerCase(),
    p_resource_id: resourceId,
    p_recipient_id: recipientId,
    p_level: level,
    p_wrapped_key: wrappedKey,
    p_ephemeral_public_key: ephemeralPublicKey,
    p_expires_at: expiresAt,
  });
  if (error) throw fail(error);
  return { shareId: data };
}

/** Ends a share: access stops at once and the recipient's key grant is deleted. */
export async function revokeShare(shareId) {
  const { error } = await getSupabase().rpc("revoke_share", {
    p_share_id: shareId,
  });
  if (error) throw fail(error);
}

/** Who a folder you own is shared with: [{ shareId, recipientId, email, name, level, createdAt, expiresAt }]. */
export async function listShares(resourceId) {
  const { data, error } = await getSupabase().rpc("list_shares_for_resource", {
    p_resource_id: resourceId,
    p_resource_type: "folder",
  });
  if (error) throw fail(error);
  return (data ?? []).map((r) => ({
    shareId: r.share_id,
    recipientId: r.shared_with,
    email: r.recipient_email,
    name: r.recipient_name,
    level: r.level,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  }));
}

/**
 * Folders shared with you, each with the encrypted folder name and YOUR key grant for it:
 * [{ shareId, folderId, level, createdAt, expiresAt, ownerName, ownerEmail, nameEnc, wrappedKey, ephemeralPublicKey }].
 * A share without a readable folder or key grant is left out.
 */
export async function listSharedWithMe() {
  const supabase = getSupabase();
  const me = await currentUserId();
  const { data: shares, error } = await supabase.rpc("get_shared_with_me");
  if (error) throw fail(error);
  const folderShares = (shares ?? []).filter(
    (s) => s.resource_type === "folder",
  );
  if (!folderShares.length) return [];
  const ids = folderShares.map((s) => s.resource_id);

  const [
    { data: folders, error: folderError },
    { data: envelopes, error: envError },
  ] = await Promise.all([
    supabase.from("folders").select("folder_id, name_enc").in("folder_id", ids),
    supabase
      .from("key_envelopes")
      .select("resource_id, wrapped_key, ephemeral_public_key")
      .eq("recipient_id", me)
      .eq("resource_type", "folder")
      .in("resource_id", ids),
  ]);
  if (folderError) throw fail(folderError);
  if (envError) throw fail(envError);

  const out = [];
  for (const s of folderShares) {
    const folder = folders?.find((f) => f.folder_id === s.resource_id);
    const env = envelopes?.find((e) => e.resource_id === s.resource_id);
    if (!folder?.name_enc || !env) continue;
    out.push({
      shareId: s.share_id,
      folderId: s.resource_id,
      level: s.level,
      createdAt: s.created_at,
      expiresAt: s.expires_at ?? null,
      ownerName: s.owner_name,
      ownerEmail: s.owner_email,
      nameEnc: folder.name_enc,
      wrappedKey: env.wrapped_key,
      ephemeralPublicKey: env.ephemeral_public_key,
    });
  }
  return out;
}

/**
 * The shared folder `rootId` and everything under it, still encrypted: [{ id, parentId, nameEnc, wrappedKey }],
 * root first with parentId null. Empty when the folder is not (or no longer) shared with you.
 */
export async function listSharedSubtree(rootId) {
  const me = await currentUserId();
  const { data, error } = await getSupabase()
    .from("folders")
    .select("folder_id, parent_id, name_enc, wrapped_key")
    .neq("owner_id", me)
    .not("name_enc", "is", null)
    .order("created_at", { ascending: true });
  if (error) throw fail(error);

  const rows = data ?? [];
  const root = rows.find((r) => r.folder_id === rootId);
  if (!root) return [];
  const out = [
    {
      id: root.folder_id,
      parentId: null,
      nameEnc: root.name_enc,
      wrappedKey: root.wrapped_key,
    },
  ];
  const queue = [rootId];
  while (queue.length) {
    const parent = queue.shift();
    for (const r of rows.filter((x) => x.parent_id === parent)) {
      out.push({
        id: r.folder_id,
        parentId: parent,
        nameEnc: r.name_enc,
        wrappedKey: r.wrapped_key,
      });
      queue.push(r.folder_id);
    }
  }
  return out;
}
