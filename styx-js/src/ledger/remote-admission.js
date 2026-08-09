// Fail-closed containment for the unsafe v1 remote ledger ingress.

export const V1_REMOTE_ADMISSION_DISABLED_CODE =
  'STYX_V1_REMOTE_ADMISSION_DISABLED';

export const V1_REMOTE_ADMISSION_DISABLED_MESSAGE =
  'Styx v1 remote ledger admission is disabled until safe bootstrap and atomic admission are implemented.';

export const V1_REMOTE_ADMISSION_DISABLED_RESULT = Object.freeze({
  accepted: false,
  code: V1_REMOTE_ADMISSION_DISABLED_CODE,
  message: V1_REMOTE_ADMISSION_DISABLED_MESSAGE,
});
