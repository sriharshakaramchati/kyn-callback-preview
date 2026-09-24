export const PROVIDER_ID = "0a2c911b-79ab-41f1-8864-59fea860baaf";
export const BODY_LIMIT = 25 * 1024 * 1024;
export const SESSION_TTL = 30 * 60 * 1000;
export const RESULT_TTL = 60 * 60 * 1000;
// One large proof at a time on the free 512 MB callback instance.
export const MAX_ACTIVE_VERIFICATIONS = 1;
export const MAX_PROOFS = 2048;
export class SafeError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}
export function requireCondition(condition, status, code) {
  if (!condition) throw new SafeError(status, code);
}
