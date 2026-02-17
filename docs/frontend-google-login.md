# Frontend Google Login Integration Guide

This guide describes what to implement on the frontend so Google login works with the backend OAuth flow.

## Overview

The backend returns the same auth payload as email login: `accessToken`, `refreshToken`, and `user`. After Google sign-in, the user is redirected to your frontend with these values in the URL **hash fragment** (and optionally in cookies). The frontend should store tokens and user the same way as after a normal login so the rest of the app does not need to change.

## 1. Google Login Button

On the login page, add a **“Sign in with Google”** button that sends the user to the backend OAuth start URL (full-page redirect, no popup):

- **URL:** `GET ${backendBaseUrl}/v1/api/auth/google`
- **Backend base URL:** Use an env variable (e.g. `VITE_API_BASE_URL` so it works in dev and production.

Example (pseudo-code):

```ts
const apiBaseUrl = import.meta.env.VITE_API_BASE_URL; // or your env key
const googleLoginUrl = `${apiBaseUrl}/v1/api/auth/google`;

// Button/link
<a href={googleLoginUrl}>Sign in with Google</a>
```

## 2. Callback Route (`/auth/callback`)

Add a route (e.g. `/auth/callback`) that runs after the backend redirects back from Google.

### 2.1 Read tokens and user from the hash

The backend redirects to:

`${frontendOrigin}/auth/callback#accessToken=...&refreshToken=...&user=...`

- **Hash fragment:** Use `window.location.hash` and parse it (e.g. `URLSearchParams` with the hash string without `#`).
- **Parameters:**
  - `accessToken` – JWT access token
  - `refreshToken` – JWT refresh token
  - `user` – JSON string of the user object: `{ id, email, emailVerified, isTwoFaEnabled, roles, mustChangePassword }`

### 2.2 Store tokens and user

- Store tokens the **same way** as after email login (e.g. in memory, localStorage, or your auth store).
- Parse `user` with `JSON.parse()` and store it in your auth state so the app sees the user as logged in.

### 2.3 Redirect after success

- Clear the hash or navigate away so tokens are not left in the URL.
- Redirect to the post-login destination (e.g. dashboard or home). If you later add `redirectPath` to the fragment, use that.

### 2.4 Optional: cookies

If the frontend and backend share a domain or you use credentials, the backend also sets `accessToken` and `refreshToken` in cookies. You can rely on cookies for API calls instead of (or in addition to) the hash. If the callback has no hash but the user is authenticated via cookies, you can call `GET /v1/api/auth/status` with credentials to get the user and then redirect.

## 3. Error Handling

- If the user lands on `/auth/callback` **without** a hash (and no valid session/cookies), redirect to login with an error, e.g. `/login?error=oauth_failed`.
- If the backend adds an `error` query param to the redirect in the future, show an appropriate message.

## 4. CORS and cookies

- Backend uses `credentials: true` and allows origins from `ALLOWED_ORIGINS` or `HOME_HEALTH_AI_URL` / `FRONTEND_URL`.
- Ensure your frontend origin is allowed so cookie-based auth works if you use it.
- For cross-origin (e.g. frontend on port 5173, backend on 8000), use the **hash fragment** for tokens; cookies may not be sent cross-origin unless SameSite and domain are configured accordingly.

## 5. Flow Summary

1. User clicks “Sign in with Google” → browser goes to `GET ${backend}/v1/api/auth/google`.
2. Backend redirects to Google; user signs in with Google.
3. Google redirects to backend callback (`GOOGLE_CALLBACK_URL`).
4. Backend runs `googleLogin()`, sets cookies, and redirects to `${frontendUrl}/auth/callback#accessToken=...&refreshToken=...&user=...`.
5. Frontend loads `/auth/callback`, parses the hash, stores tokens and user, then redirects to the app (e.g. dashboard).

After step 5, the app state should match a normal login (same tokens and user shape), so existing auth checks and API usage continue to work.
