/**
 * HSM Attestation Validation
 *
 * TODO: implementacja jutro
 * POST https://api.encedo.com/... { genuine }
 * 200 → valid, dodatkowe dane w JSON
 * 400 → niewazny genuine
 */

// TODO: const BROKER_URL = (process.env.ENCEDO_BROKER_URL || 'https://api.encedo.com').replace(/\/+$/, '');

export async function validateAttestation(genuine) {
  if (typeof genuine !== 'string' || genuine.length === 0) {
    return { hw_attested: 'false' };
  }

  // TODO: POST ${BROKER_URL}/... { genuine }
  // 200 → hw_attested: 'true'
  // 400 → hw_attested: 'false'

  return { hw_attested: 'true' };
}
