/**
 * Domain validation (M10) — mirrors backend/utils/domain_validation.py.
 * Both sides MUST stay in lock-step. The wizard relies on byte-identical
 * client/server rejection semantics.
 *
 * RFC 1035 / RFC 5890 hostname/domain label rules; allows leading wildcard.
 */

export const DOMAIN_REGEX =
  /^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
export const MAX_DOMAIN_LENGTH = 253;

/**
 * Validate + normalise a single domain. Returns the normalised value, or
 * throws an Error with a human-readable message when invalid.
 */
export function validateDomain(value) {
  if (!value || typeof value !== 'string') {
    throw new Error('Domain entries must be non-empty strings');
  }
  const dNorm = value.trim().toLowerCase();
  if (!dNorm || dNorm.length > MAX_DOMAIN_LENGTH) {
    throw new Error(`Invalid domain length: '${value}' (max ${MAX_DOMAIN_LENGTH} chars)`);
  }
  if (dNorm.includes('..') || dNorm.startsWith('.') || dNorm.endsWith('.')) {
    throw new Error(`Invalid domain syntax: '${value}'`);
  }
  if (!DOMAIN_REGEX.test(dNorm)) {
    throw new Error(`Invalid domain format: '${value}'`);
  }
  return dNorm;
}

/**
 * Antd Form rule wrapper for a single-domain input.
 */
export const antdDomainRule = {
  validator: (_, value) => {
    if (!value) return Promise.resolve();
    try {
      validateDomain(value);
      return Promise.resolve();
    } catch (e) {
      return Promise.reject(new Error(e.message));
    }
  },
};

/**
 * Antd Form rule wrapper for a list of domains (comma-separated string OR
 * array of strings).
 */
export const antdDomainsListRule = {
  validator: (_, value) => {
    if (!value) return Promise.resolve();
    const items = Array.isArray(value)
      ? value
      : String(value)
          .split(/[\s,;]+/)
          .map((x) => x.trim())
          .filter(Boolean);
    try {
      for (const d of items) validateDomain(d);
      return Promise.resolve();
    } catch (e) {
      return Promise.reject(new Error(e.message));
    }
  },
};
