/**
 * HSM Attestation Validation
 *
 * Flow:
 *  1. Frontend: GET {hsm_url}/api/system/config/attestation -> genuine blob
 *  2. Frontend sends genuine to backend via POST /enrollment/submit
 *  3. Backend: POST https://api.encedo.com/attest with the genuine blob (1:1 forward)
 *  4. { result: "ok" } -> hw_attested = true
 */

const ATTEST_URL = 'https://api.encedo.com/attest';

export async function validateAttestation(genuine, crt) {
  if (genuine == null || genuine === '') {
    console.warn('[Attestation] No genuine blob -- skipping api.encedo.com/attest');
    return { hw_attested: 'false', reason: 'no_genuine' };
  }

  const payload = { genuine, ...(crt ? { crt } : {}) };
  // Verbose logging is intentional -- attestation failures are hard to diagnose
  // in production without the full request/response pair.
  console.log('[Attestation] -> POST', ATTEST_URL);
  console.log('[Attestation]   body:', JSON.stringify(payload));

  try {
    const res = await fetch(ATTEST_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      signal:  AbortSignal.timeout(10_000),
    });

    let data = null;
    try { data = await res.json(); } catch { /* non-JSON body */ }

    console.log(`[Attestation] <- HTTP ${res.status}:`, JSON.stringify(data));

    if (res.ok && data?.result === 'ok') {
      // api.encedo.com already validates timestamp freshness -- trust the result directly.
      return { hw_attested: 'true', crt: crt ?? undefined };
    }

    const reason = data?.error ?? data?.reason ?? `http_${res.status}`;
    return { hw_attested: 'false', reason };

  } catch (err) {
    console.error('[Attestation] Request failed:', err.message);
    return { hw_attested: 'false', reason: 'network_error' };
  }
}
