/**
 * Centralny handler błędów Express.
 * Używaj: next(err) w route handlerach.
 */
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  const status = err.status ?? 500;
  const message = err.message ?? 'internal_server_error';

  if (status === 500) {
    console.error('[Error]', err);
  }

  res.status(status).json({ error: message });
}
