import { SafeError } from './constants.mjs';

// Only these constant codes may cross the SDK worker boundary. SDK messages can
// contain contact fields, signed contexts or full request URLs: never forward them.
const statuses = Object.freeze({
  INVALID_PROOF: 422,
  PROOF_SIGNATURE_INVALID: 422,
  PROOF_HTTP_PARAMS_INVALID: 422,
  PROVIDER_CONTENT_MISMATCH: 422,
  UNEXPECTED_PROOF: 422,
  INCOMPLETE_PROOF: 422,
  PROVIDER_SCHEMA_CHANGED: 422,
  PROVIDER_VERSION_UNAVAILABLE: 422,
  PROVIDER_CONFIG_UNAVAILABLE: 503,
  VERIFICATION_UNAVAILABLE: 503,
});

export function verificationFailure(error) {
  let code = 'INVALID_PROOF';
  if (error instanceof SafeError && Object.hasOwn(statuses, error.code)) {
    code = error.code;
  } else if (error?.name === 'ProviderConfigFetchError') {
    code = 'PROVIDER_CONFIG_UNAVAILABLE';
  } else if (error?.name === 'ProofNotVerifiedError') {
    code = 'PROOF_SIGNATURE_INVALID';
  } else if (error?.name === 'UnknownProofsNotValidatedError') {
    code = 'UNEXPECTED_PROOF';
  } else if (error?.name === 'ProofNotValidatedError') {
    code = error.message === 'Proof has no HTTP provider params to hash'
      ? 'PROOF_HTTP_PARAMS_INVALID' : 'PROVIDER_CONTENT_MISMATCH';
  }
  return new SafeError(statuses[code], code);
}

export function workerFailure(message) {
  const code = Object.hasOwn(statuses, message?.code) ? message.code : 'INVALID_PROOF';
  return new SafeError(statuses[code], code);
}
