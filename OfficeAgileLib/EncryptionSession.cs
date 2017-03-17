using System;
using System.IO;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Represents an instance of document encryption
    /// </summary>
    public class EncryptionSession
    {
        private HashConfig hashConfig;
        private CipherConfig cipherConfig;
        private byte[] saltValue;
        private KeyManager keyManager;
        private PrimaryCipher primaryCipher;
        private HmacData hmacData;

        public bool IsUnlocked { get { return this.keyManager.IsUnlocked; } }
        public int CipherBlockBytes { get { return cipherConfig.BlockBits / 8; } }

        public static EncryptionSession LoadFromStream(Stream stream, bool useHmac)
        {
            EncryptionConfig encryptionConfig;
            var encryptionData = EncryptionData.LoadFromStream(stream, useHmac, out encryptionConfig);
            return new EncryptionSession(encryptionConfig, encryptionData);
        }

        public static EncryptionSession LoadFromStream(Stream stream)
        {
            return LoadFromStream(stream, true);
        }

        public EncryptionSession(EncryptionConfig config)
        {
            Log.PushScope("EncryptionSession::EncryptionSession");

            this.cipherConfig = config.CipherConfig.Copy();
            this.hashConfig = config.HashConfig.Copy();
            this.saltValue = new byte[config.SaltSize];
            RandomNumberGenerator.Create().GetBytes(this.saltValue);
            Log.WriteBytes("MainSaltValue", this.saltValue);

            this.keyManager = new KeyManager(config);

            Log.PopScope();
        }

        internal EncryptionSession(EncryptionConfig config, EncryptionData data)
        {
            this.cipherConfig = config.CipherConfig.Copy();
            this.hashConfig = config.HashConfig.Copy();
            this.saltValue = data.SaltValue;

            this.keyManager = new KeyManager(config, data.PasswordEncryptorData);
            this.hmacData = data.HmacData;

            if (keyManager.SecretKey != null)
                this.primaryCipher = new PrimaryCipher(hashConfig, cipherConfig, saltValue, keyManager.SecretKey);
        }

        public bool UnlockWithPassword(string password)
        {
            if (primaryCipher != null)
                throw new InvalidOperationException("Already unlocked");

            if (!this.keyManager.UnlockWithPassword(password))
                return false;

            this.primaryCipher = new PrimaryCipher(this.hashConfig, this.cipherConfig, this.saltValue, keyManager.SecretKey);
            return true;
        }

        public void WriteToStream(Stream stream)
        {
            var config = new EncryptionConfig();
            config.CipherConfig = this.cipherConfig.Copy();
            config.HashConfig = this.hashConfig.Copy();
            config.SaltSize = this.saltValue.Length;

            var data = new EncryptionData();
            if (hmacData != null)
            {
                if (hmacData.EncryptedKey != null && hmacData.EncryptedValue != null)
                    data.HmacData = this.hmacData.Copy();
            }
            data.SaltValue = this.saltValue;

            this.keyManager.Save(config, data);
            EncryptionData.WriteToStream(stream, config, data);
        }

        public EncryptedStream GetEncryptedStream(Stream stream)
        {
            if (primaryCipher == null)
                throw new InvalidOperationException("Not unlocked");

            return new EncryptedStream(this.primaryCipher, stream);
        }

        public void AddIntegrityCheck(Stream stream)
        {
            if (primaryCipher == null)
                throw new InvalidOperationException("Not unlocked");

            this.hmacData = Hmac.GetHmac(this.primaryCipher, this.hashConfig, stream);
        }

        public bool DoIntegrityCheck(Stream stream)
        {
            if (primaryCipher == null)
                throw new InvalidOperationException("Not unlocked");
            if (this.hmacData == null)
                return true;

            return Hmac.CheckStream(this.primaryCipher, this.hashConfig, this.hmacData, stream);
        }

        public ICryptoTransform GetEncryptor()
        {
            return primaryCipher.GetEncryptor(0, 0);
        }

        public ICryptoTransform GetDecryptor()
        {
            return primaryCipher.GetDecryptor(0, 0);
        }

        internal void Save(out EncryptionConfig config, out EncryptionData data)
        {
            config = new EncryptionConfig
            {
                CipherConfig = cipherConfig.Copy(),
                HashConfig = hashConfig.Copy(),
                SaltSize = saltValue.Length
            };

            data = new EncryptionData();
            if (hmacData != null)
            {
                if (hmacData.EncryptedKey != null && hmacData.EncryptedValue != null)
                    data.HmacData = hmacData.Copy();
            }
            data.SaltValue = saltValue;

            keyManager.Save(config, data);
        }

    }
}
