/**
 * Central Express error handler. Use: next(err) in route handlers.
 */
// Express requires exactly 4 params to recognise this as an error handler.
export function errorHandler(err, _req, res, _next) {
  const status = err.status ?? 500;
  const message = err.message ?? 'internal_server_error';

  if (status === 500) {
    console.error('[Error]', err);
  }

  res.status(status).json({ error: message });
}
