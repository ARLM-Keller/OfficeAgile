using System;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// A small class to manage the secret key, and the KeyEncryptors
    /// </summary>
    class KeyManager
    {
        private PasswordKeyEncryptor passwordKeyEncryptor;
        private byte[] secretKey;

        public bool IsLocked { get { return this.secretKey == null; } }
        public bool IsUnlocked { get { return !this.IsLocked; } }
        public byte[] SecretKey { get { return this.secretKey; } }
        public PasswordKeyEncryptor PasswordKeyEncryptor { get { return passwordKeyEncryptor; } }

        public KeyManager(EncryptionConfig config)
        {
            Log.PushScope("KeyManager::KeyManager");

            this.secretKey = new byte[config.CipherConfig.BlockBits / 8];
            RandomNumberGenerator.Create().GetBytes(this.secretKey);
            Log.WriteBytes("NewSecretKey", this.secretKey);

            this.passwordKeyEncryptor = new PasswordKeyEncryptor(config.PasswordKeyEncryptorConfig);

            Log.PopScope();
        }

        public KeyManager(EncryptionConfig config, PasswordKeyEncryptorData data)
        {
            this.passwordKeyEncryptor = new PasswordKeyEncryptor(config.PasswordKeyEncryptorConfig, data);

            if (data.SecretKey != null)
                secretKey = (byte[])data.SecretKey.Clone();

            // TODO: store other encryptors
        }

        public void SetPassword(string password)
        {
            if (this.secretKey == null)
                throw new InvalidOperationException("Not unlocked");

            this.passwordKeyEncryptor.SetPassword(password, this.secretKey);
        }

        public bool UnlockWithPassword(string password)
        {
            if (this.secretKey != null)
                throw new InvalidOperationException("Already unlocked");

            return this.passwordKeyEncryptor.TryUnlock(password, out this.secretKey);
        }

        internal void Save(EncryptionConfig config, EncryptionData data)
        {
            config.PasswordKeyEncryptorConfig = new PasswordKeyEncryptorConfig();
            data.PasswordEncryptorData = new PasswordKeyEncryptorData();
            data.PasswordEncryptorData.SecretKey = secretKey;
            this.passwordKeyEncryptor.Save(config.PasswordKeyEncryptorConfig, data.PasswordEncryptorData);
        }
    }
}
