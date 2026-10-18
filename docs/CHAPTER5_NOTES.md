# Chapter 5 notes — Interface, Phase 1 (draft)

- **Stack:** React 18 + Vite, React Router, plain CSS with design tokens. No UI framework, to keep the
  prototype small and the code easy to explain.
- **Layering:** pages -> AuthContext -> authApi (mock or real) and cryptoBridge. Pages never see keys,
  salts or hashing; this realises the usability requirement that users do not manage cryptography.
- **Contract as code:** `services/contract.js` encodes the API Agreements sheet; the mock rejects
  requests that drift from it, so contract mismatches surface in Phase 1, not integration.
- **Security-relevant UI decisions:** session kept in memory only; generic login error; password never
  placed in a request; frontend validation treated as UX, not security (Table 4.16, agreements #6).
- **Screens built:** Register (name, email, password, confirmation, strength meter, unrecoverable-password
  warning), Login (email, password, generic error), placeholder vault page.
- **Testing:** 21 Vitest tests covering validation, mock-vs-contract behaviour and complete UI flows.
- **Known limitation:** the salt/authSecret ordering problem at login (see OPEN_QUESTIONS.md).
