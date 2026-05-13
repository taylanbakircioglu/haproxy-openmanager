import React from 'react';
import ReactDOM from 'react-dom/client';
import axios from 'axios';
import './index.css';
import App from './App';

// ---------------------------------------------------------------------------
// Axios auth bootstrap (module-load phase)
//
// Why this exists at module-load time, BEFORE the React tree renders:
//
//   The provider hierarchy is <AuthProvider><ClusterProvider>… and React's
//   useEffect commit phase fires CHILD effects before PARENT effects. That
//   means `ClusterProvider.useEffect` (which dispatches the very first
//   `axios.get('/api/clusters')`) runs BEFORE `AuthProvider.useEffect`
//   (which is where the legacy code path used to set
//   `axios.defaults.headers.common['Authorization']`). On a fresh page load
//   the first cluster request therefore went out with NO Authorization
//   header → backend returned 401 → ClusterContext's catch block silently
//   set `clusters=[]` → operators saw "no clusters" until the 30-second
//   auto-refresh interval re-fired and the second request happened to land
//   AFTER AuthProvider's effect had populated the header. Operators
//   experienced this as "I have to wait a while after deploy / I close
//   the browser and re-open and clusters still don't appear for a while".
//
// Fix:
//   1) Read the token from localStorage at module-load and seed
//      `axios.defaults.headers.common['Authorization']` synchronously, so
//      child-effects that fire BEFORE AuthProvider's effect already have
//      a populated default header.
//   2) Install an `axios.interceptors.request` that re-reads the token
//      on every outbound request. This is the belt-and-suspenders defence
//      against any future code path that clears or mutates the default
//      header — the interceptor cannot be raced by mount ordering because
//      it's installed before <App /> renders and runs synchronously per
//      request.
//
// Both layers are no-ops when the user is not logged in (no token in
// localStorage) and when the stored token is expired — the backend will
// return 401 and the existing AuthContext logout path handles re-login.
// ---------------------------------------------------------------------------
(function bootstrapAxiosAuth() {
  try {
    const token =
      localStorage.getItem('token') || localStorage.getItem('authToken');
    const tokenExpiry = localStorage.getItem('tokenExpiry');
    if (token && tokenExpiry && new Date(tokenExpiry) > new Date()) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
  } catch (_) {
    // localStorage unavailable (privacy mode / SSR shim) — fall through.
    // The interceptor below still guards live requests if the storage
    // becomes available later.
  }

  axios.interceptors.request.use(
    (config) => {
      try {
        // Only attach Authorization when the caller hasn't explicitly set
        // one — preserves opt-out call sites (e.g. /api/auth/login which
        // intentionally posts unauthenticated).
        const hasExplicitAuth =
          config.headers &&
          (config.headers.Authorization ||
            config.headers.authorization ||
            (config.headers.common &&
              (config.headers.common.Authorization ||
                config.headers.common.authorization)));
        if (hasExplicitAuth) return config;

        const token =
          localStorage.getItem('token') || localStorage.getItem('authToken');
        const tokenExpiry = localStorage.getItem('tokenExpiry');
        if (token && tokenExpiry && new Date(tokenExpiry) > new Date()) {
          config.headers = config.headers || {};
          config.headers.Authorization = `Bearer ${token}`;
        }
      } catch (_) {
        // Best-effort. Never let interceptor errors fail the actual
        // request — let the backend return its normal 401 if the header
        // is missing for any reason.
      }
      return config;
    },
    (error) => Promise.reject(error)
  );
})();

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
