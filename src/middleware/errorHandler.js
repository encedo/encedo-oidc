/**
 * Central Express error handler. Use: next(err) in route handlers.
 */
// Express requires exactly 4 params to recognise this as an error handler.
export function errorHandler(err, _req, res, _next) {
  const status = err.status ?? err.statusCode ?? 500;

  if (status >= 500) {
    // Unexpected exception: log it server-side, but never return err.message to
    // the client -- it can leak stack details, file paths or Redis internals.
    console.error('[Error]', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }

  // Raw system/framework errors (e.g. res.sendFile ENOENT, EACCES) put a
  // filesystem path in err.message -- return a generic instead of leaking it.
  if (err.code) {
    return res.status(status).json({ error: 'request_failed' });
  }

  // A deliberately-set status (err.status) carries a chosen, safe message.
  res.status(status).json({ error: err.message ?? 'error' });
}
