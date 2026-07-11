// config.js — fail-fast configuration for the FidesVox demo.
//
// The demo must NOT ship a hardcoded auth secret. The JWT signing secret is read from the
// environment and validated at startup; a missing or weak value STOPS the demo rather than
// silently signing session tokens with a guessable key.

const WEAK = new Set([
  'changeme', 'change-me', 'secret', 'password', 'passphrase',
  'dev', 'test', 'demo', 'fidesvox', 'jwt', 'jwtsecret',
]);

const HOWTO =
  "  JWT_SECRET=$(node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\") node demo/fidesvox/server.js\n" +
  '  (or put JWT_SECRET in a local .env — see demo/fidesvox/.env.example)';

/**
 * Resolve and validate the JWT signing secret from the environment.
 * @param {Record<string,string|undefined>} env typically process.env
 * @returns {string} the validated secret
 * @throws {Error} if the secret is missing or too weak
 */
export function requireJwtSecret(env = {}) {
  const value = env.JWT_SECRET;
  if (!value || typeof value !== 'string') {
    throw new Error(`FidesVox demo: JWT_SECRET is required.\n${HOWTO}`);
  }
  if (value.length < 32 || WEAK.has(value.toLowerCase())) {
    throw new Error(
      `FidesVox demo: JWT_SECRET is too weak — use at least 32 chars of high-entropy randomness.\n${HOWTO}`,
    );
  }
  return value;
}
