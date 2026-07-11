// A crypto-module failure the app must NOT paper over. Surfaced to the user as a
// hard stop, never as a silent downgrade to fake data.
export class FatalCryptoError extends Error {
  constructor(cause) {
    super("Il modulo crittografico non è disponibile. L'app non può avviarsi in sicurezza.");
    this.name = 'FatalCryptoError';
    this.cause = cause;
  }
}
