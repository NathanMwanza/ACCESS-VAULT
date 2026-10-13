// Phase 2: the real endpoints (Prince). Same two functions as the mock, so
// switching is VITE_USE_MOCK=false and nothing else changes.

import { postJson, ApiError } from './apiClient.js';
import { ERROR_CODES, isLoginResponse, isRegisterResponse } from './contract.js';

export async function register(payload) {
  const data = await postJson('/auth/register', payload);
  if (!isRegisterResponse(data)) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'The server sent an unexpected response.');
  }
  return data;
}

export async function login(payload) {
  const data = await postJson('/auth/login', payload);
  if (!isLoginResponse(data)) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'The server sent an unexpected response.');
  }
  return data;
}
