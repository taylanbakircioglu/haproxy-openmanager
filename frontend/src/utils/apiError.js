/**
 * v1.5.0 R16 #v3 — envelope-aware error extractor.
 *
 * The backend's GlobalExceptionHandler wraps EVERY error in a custom
 * envelope:
 *
 *   {
 *     "error": {
 *       "message": "...",
 *       "type": "...",
 *       "correlation_id": "...",
 *       "details": { "validation_errors": [{ "field", "message", "type" }] }
 *     }
 *   }
 *
 * — NOT FastAPI's default `{ "detail": ... }`. Components that read
 * `err.response.data.detail` always got `undefined` and ended up
 * showing a generic "Request failed" toast, swallowing the real
 * server-side reason (validation field path, RBAC denial, collision
 * warning, …).
 *
 * extractApiError handles the modern envelope first (so users see the
 * actual reason), then falls back to the plain `detail` shape so any
 * legacy endpoint that still returns the old format keeps working.
 *
 * @param {*} err - axios error (must have err.response.data)
 * @param {string} [fallback] - message to use when no shape matches
 * @returns {string} a user-facing message
 */
export const extractApiError = (err, fallback = 'Request failed') => {
  const data = err?.response?.data;
  if (!data) return fallback;

  // Modern envelope path
  const env = data.error;
  if (env && typeof env === 'object') {
    const ve = env.details?.validation_errors;
    if (Array.isArray(ve) && ve.length) {
      return ve
        .map((v) => `${v.field || '?'}: ${v.message || v.msg || ''}`.trim())
        .join(' · ');
    }
    if (typeof env.message === 'string' && env.message) return env.message;
  }

  // Legacy / plain FastAPI shape
  const detail = data.detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => `${(d.loc || []).join('.')}: ${d.msg || ''}`.trim())
      .join(' · ');
  }
  if (typeof detail === 'string' && detail) return detail;

  return fallback;
};

export default extractApiError;
