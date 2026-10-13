// Pages and context import `authApi` from here and never care which one it is.
// Swap mock <-> real with VITE_USE_MOCK (default: mock). No page code changes.

import * as mockAuthApi from './mock/mockAuthApi.js';
import * as realAuthApi from './realAuthApi.js';

export const USING_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';

export const authApi = USING_MOCK ? mockAuthApi : realAuthApi;
