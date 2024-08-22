using ComponentSpace.SAML2.Data;
using StackExchange.Redis;
using System;

namespace ComponentSpace.SAML2.Redis
{
    /// <summary>
    /// Implements the ISSOSessionStore using Redis.
    /// 
    /// Usage: SAMLController.SSOSessionStore = new RedisSSOSessionStore();
    /// </summary>
    public class RedisSSOSessionStore : AbstractSSOSessionStore
    {
        private static readonly TimeSpan defaultExpiry = new TimeSpan(1, 0, 0);
        private static readonly ConnectionMultiplexer redis = ConnectionMultiplexer.Connect("localhost");

        /// <summary>
        /// Loads the SSO session object.
        /// </summary>
        /// <param name="type">The SSO session object type.</param>
        /// <returns>The SSO session object or <c>null</c> if none.</returns>
        public override object Load(Type type)
        {
            var db = redis.GetDatabase();
            var key = CreateSessionIDForType(type);
            byte[] bytes = db.StringGet(key);

            if (bytes != null)
            {
                return Deserialize(bytes);
            }

            return null;
        }

        /// <summary>
        /// Saves the SSO session object.
        /// </summary>
        /// <param name="ssoSession">The serializable SSO session object.</param>
        public override void Save(object ssoSession)
        {
            var db = redis.GetDatabase();
            var key = CreateSessionIDForType(ssoSession.GetType());
            byte[] bytes = Serialize(ssoSession);

            db.StringSet(key, bytes, defaultExpiry);
        }

        /// <summary>
        /// Deletes the SSO session object.
        /// </summary>
        /// <param name="type">The SSO session object type.</param>
        public override void Delete(Type type)
        {
            var db = redis.GetDatabase();
            var key = CreateSessionIDForType(type);

            db.KeyDelete(key);
        }
    }
}
