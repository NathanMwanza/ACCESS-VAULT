// Pages and context import `authApi` from here and never care which one it is.
// Swap mock <-> Supabase with VITE_USE_MOCK (default: mock). No page code changes.
//
// Both sides expose the same functions, which authFlow.js calls through configure({ backend }):
//   getAuthParams, register, login, logout, createFolder, createGrant, getVault, listFolders,
//   createFile, uploadChunk, completeFile, listFiles, getFile, downloadChunk, deleteFile,
//   findShareTarget, shareResource, revokeShare, listShares, listSharedWithMe, listSharedSubtree

import * as mockAuthApi from './mock/mockAuthApi.js';
import * as supabaseAuthApi from './supabaseAuthApi.js';
import * as supabaseVaultApi from './supabaseVaultApi.js';
import * as supabaseFilesApi from './supabaseFilesApi.js';
import * as supabaseSharingApi from './supabaseSharingApi.js';

export const USING_MOCK = import.meta.env?.VITE_USE_MOCK !== 'false';

export const authApi = USING_MOCK ? mockAuthApi : { ...supabaseAuthApi, ...supabaseVaultApi, ...supabaseFilesApi, ...supabaseSharingApi };
