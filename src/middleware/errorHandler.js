/**
 * Central Express error handler. Use: next(err) in route handlers.
 */
// Express requires exactly 4 params to recognise this as an error handler.
export function errorHandler(err, _req, res, _next) {
  const status = err.status ?? 500;

  if (status === 500) {
    // Unexpected exception: log it server-side, but never return err.message to
    // the client -- it can leak stack details, file paths or Redis internals.
    console.error('[Error]', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }

  // A deliberately-set status (err.status) carries a chosen, safe message.
  res.status(status).json({ error: err.message ?? 'error' });
}
