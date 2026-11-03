// Vault folder + key-grant calls used by authFlow.js. Everything stored here is ciphertext:
// folder names are encrypted in the browser (nameEnc) and keys are wrapped to a recipient's
// public key, so the database never sees a name or a key in the clear.
//
// Needs supabase/migrations/002_vault_folders_and_grants.sql. Row Level Security is the real
// boundary: a signed-in user can only create folders they own and read keys addressed to them.
//
// Mapping to tables:  "folder"  -> public.folders       (name_enc, wrapped_key)
//                     "grant"   -> public.key_envelopes (wrapped_key, ephemeral_public_key, role)

import { ApiError } from "./apiClient.js";
import { ERROR_CODES } from "./contract.js";
import { getSupabase } from "./supabaseClient.js";

function fail(error) {
  console.error("[supabase]", error);
  const network =
    error?.name === "AuthRetryableFetchError" ||
    /failed to fetch|network/i.test(String(error?.message ?? ""));
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

/** { nameEnc, parentId, wrappedKey } -> { folderId } */
export async function createFolder({
  nameEnc,
  parentId = null,
  wrappedKey = null,
}) {
  const ownerId = await currentUserId();
  const { data, error } = await getSupabase()
    .from("folders")
    .insert({
      owner_id: ownerId,
      parent_id: parentId,
      name_enc: nameEnc,
      wrapped_key: wrappedKey,
    })
    .select("folder_id")
    .single();
  if (error) throw fail(error);
  return { folderId: data.folder_id };
}

/**
 * Every encrypted folder the signed-in user OWNS (the vault root and all subfolders), oldest first.
 * Folders shared with them are not listed here: those arrive through key grants.
 * Returns [{ id, parentId, nameEnc, wrappedKey }]; the browser decrypts the names.
 */
export async function listFolders() {
  const me = await currentUserId();
  const { data, error } = await getSupabase()
    .from("folders")
    .select("folder_id, parent_id, name_enc, wrapped_key")
    .eq("owner_id", me)
    .not("name_enc", "is", null)
    .order("created_at", { ascending: true });
  if (error) throw fail(error);
  return (data ?? []).map((r) => ({
    id: r.folder_id,
    parentId: r.parent_id,
    nameEnc: r.name_enc,
    wrappedKey: r.wrapped_key,
  }));
}

/** { resourceType: 'FOLDER'|'FILE', resourceId, granteeId, role, wrappedKey, ephemeralPublicKey } -> { grantId } */
export async function createGrant({
  resourceType,
  resourceId,
  granteeId,
  role,
  wrappedKey,
  ephemeralPublicKey,
}) {
  const { data, error } = await getSupabase()
    .from("key_envelopes")
    .insert({
      resource_type: String(resourceType).toLowerCase(),
      resource_id: resourceId,
      recipient_id: granteeId,
      role,
      wrapped_key: wrappedKey,
      ephemeral_public_key: ephemeralPublicKey,
    })
    .select("envelope_id")
    .single();
  if (error) throw fail(error);
  return { grantId: data.envelope_id };
}

/**
 * The user's vault: their top-level encrypted folder plus the key grant addressed to them.
 * Returns null when there is none yet (first login after an interrupted registration).
 * Folders made by the old "Backend check" panel have no name_enc and are ignored.
 */
export async function getVault() {
  const supabase = getSupabase();
  const me = await currentUserId();

  const { data: roots, error: foldersError } = await supabase
    .from("folders")
    .select("folder_id, name_enc")
    .eq("owner_id", me)
    .is("parent_id", null)
    .not("name_enc", "is", null)
    .order("created_at", { ascending: true });
  if (foldersError) throw fail(foldersError);
  if (!roots?.length) return null;

  const { data: envelopes, error: envError } = await supabase
    .from("key_envelopes")
    .select("resource_id, wrapped_key, ephemeral_public_key")
    .eq("recipient_id", me)
    .eq("resource_type", "folder")
    .in(
      "resource_id",
      roots.map((r) => r.folder_id),
    );
  if (envError) throw fail(envError);

  // The oldest root that has a key for us. A root with no grant (registration died half way) is skipped.
  for (const root of roots) {
    const env = envelopes?.find((e) => e.resource_id === root.folder_id);
    if (env) {
      return {
        id: root.folder_id,
        nameEnc: root.name_enc,
        myGrant: {
          wrappedKey: env.wrapped_key,
          ephemeralPublicKey: env.ephemeral_public_key,
        },
      };
    }
  }
  return null;
}
