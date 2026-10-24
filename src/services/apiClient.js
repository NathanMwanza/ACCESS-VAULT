import { ERROR_CODES } from './contract.js';

const BASE_URL = (import.meta.env?.VITE_API_URL ?? '').replace(/\/$/, '');

/** Every failure the UI sees is one of these: { code, message, status }. */
export class ApiError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

/**
 * POST JSON and normalise errors to the agreed shape (#4):
 *   { "error": "stable_code", "message": "human-readable text" }
 * `message` is safe to show to the user directly.
 */
export async function postJson(path, body, { sessionToken } = {}) {
  let response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError(
      ERROR_CODES.NETWORK_ERROR,
      'Could not reach the server. Check your connection and try again.',
    );
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    /* non-JSON body handled below */
  }

  if (!response.ok) {
    if (data && typeof data.error === 'string') {
      throw new ApiError(data.error, data.message ?? 'Something went wrong.', response.status);
    }
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', response.status);
  }
  return data;
}