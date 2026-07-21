import redis from './redis.js';

// Revoke every active access token for a user: delete each `access:{token}` key
// and the tracking set `user_tokens:{sub}`, atomically via a single pipeline.
// Used on logout, user deletion, and re-enrollment (old key invalidated).
// Returns the number of tokens revoked.
export async function revokeUserTokens(sub) {
  const tokenKeys = await redis.sMembers(`user_tokens:${sub}`);
  if (tokenKeys.length > 0) {
    const pipeline = redis.multi();
    for (const k of tokenKeys) pipeline.del(k);
    pipeline.del(`user_tokens:${sub}`);
    await pipeline.exec();
  }
  return tokenKeys.length;
}
