using ComponentSpace.SAML2.Data;
using StackExchange.Redis;
using System;

namespace ComponentSpace.SAML2.Redis
{
    /// <summary>
    /// Implements the ID cache using Redis.
    /// 
    /// Usage: SAMLController.IDCache = new RedisIDCache();
    /// </summary>
    public class RedisIDCache : IIDCache
    {
        private static readonly TimeSpan defaultExpiry = new TimeSpan(0, 10, 0);
        private static ConnectionMultiplexer redis = ConnectionMultiplexer.Connect("localhost");

        private TimeSpan GetExpiry(DateTime expirationDateTime)
        {
            var expiry = expirationDateTime - DateTime.UtcNow;

            if (expiry.Ticks > 0)
            {
                return expiry;
            }

            return defaultExpiry;
        }

        /// <summary>
        /// Adds the ID with an associated expiration time to the cache.
        /// </summary>
        /// <param name="id">The ID.</param>
        /// <param name="expirationDateTime">The expiration time.</param>
        /// <returns><c>true</c> if the ID doesn't already exist in the cache; otherwise <c>false</c>.</returns>
        public bool Add(string id, DateTime expirationDateTime)
        {
            var db = redis.GetDatabase();
            var alreadyExists = db.KeyExists(id);

            db.StringSet(id, id, GetExpiry(expirationDateTime));

            return !alreadyExists;
        }
    }
}
