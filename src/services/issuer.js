// Public base URL of this provider.
//
// ISSUER must be set in production -- it is used verbatim for the OIDC discovery
// document and the id_token `iss` claim (see routes/oidc.js, which reads
// process.env.ISSUER directly and must NOT fall back to localhost). This helper
// exists only for building user-facing enrollment / invite / verification links,
// where a localhost fallback is a harmless dev convenience.
export function issuer() {
  return process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;
}
