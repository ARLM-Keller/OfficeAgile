using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// This class handles the password-based key derivation
    /// </summary>
    internal class PasswordBasedKey : ICipherProvider
    {
        private HashConfig hashInfo;
        private CipherConfig cipherInfo;
        private int spinCount;
        private byte[] saltValue;
        private byte[] passwordHash;

        public byte[] SaltValue
        {
            get { return (byte[])this.saltValue.Clone(); }
        }

        public int BlockBytes
        {
            get { return this.cipherInfo.BlockBits / 8; }
        }

        public int SpinCount
        {
            get { return spinCount; }
        }

        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="config"></param>
        public PasswordBasedKey(PasswordKeyEncryptorConfig config)
        {
            this.cipherInfo = config.CipherConfig.Copy();
            this.hashInfo = config.HashConfig.Copy();
            this.spinCount = config.SpinCount;

            saltValue = new byte[config.SaltSize];
            RandomNumberGenerator.Create().GetBytes(saltValue);
        }

        /// <summary>
        /// Loads from existing data
        /// </summary>
        /// <param name="config"></param>
        /// <param name="data"></param>
        public PasswordBasedKey(PasswordKeyEncryptorConfig config, PasswordKeyEncryptorData data)
        {
            this.cipherInfo = config.CipherConfig.Copy();
            this.hashInfo = config.HashConfig.Copy();
            this.spinCount = config.SpinCount;

            this.saltValue = (byte[])data.SaltValue.Clone();
        }

        public HashAlgorithm GetHashAlg() { return this.hashInfo.GetAlg(); }

        /// <summary>
        /// When the password is set, derive the hash
        /// </summary>
        /// <param name="password"></param>
        public void SetPassword(string password)
        {
            Log.PushScope("PasswordBasedKey::SetPassword");
            Log.WriteLine("Password={0}", password);

            var hashAlg = this.hashInfo.GetAlg();
            using (hashAlg)
            {
                Log.WriteBytes("SaltValue", this.saltValue);
                hashAlg.TransformBlock(this.saltValue, 0, this.saltValue.Length, null, 0);
                var passwordBytes = Encoding.Unicode.GetBytes(password);
                hashAlg.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);

                var hashValue = hashAlg.Hash;
                Log.WriteBytes("HashedSaltAndPassword", hashValue);
                for (int i = 0; i < this.spinCount; i++)
                {
                    var counterBytes = BitConverter.GetBytes(i);
                    hashAlg.Initialize();
                    hashAlg.TransformBlock(counterBytes, 0, counterBytes.Length, null, 0);
                    hashAlg.TransformFinalBlock(hashValue, 0, hashValue.Length);
                    hashValue = hashAlg.Hash;
                }

                Log.WriteBytes("FinalHashValue", hashValue);
                this.passwordHash = hashValue;
            }

            Log.PopScope();
        }

        public ICryptoTransform GetCryptoTransform(byte[] blockKey, bool isEncryption)
        {
            Log.PushScope("PasswordBasedKey::GetCryptoTransform");
            Log.WriteBytes("BlockKey", blockKey);

            var hashAlg = this.hashInfo.GetAlg();
            using (hashAlg)
            {
                Log.WriteBytes("InputHashValue", this.passwordHash);
                hashAlg.TransformBlock(this.passwordHash, 0, this.passwordHash.Length, null, 0);
                hashAlg.TransformFinalBlock(blockKey, 0, blockKey.Length);

                var secretKey = hashAlg.Hash.CloneToFit(this.cipherInfo.KeyBits / 8);
                Log.WriteBytes("SecretKey", secretKey);

                // For password derived keys, the salt is the IV
                var iv = this.SaltValue.CloneToFit(this.cipherInfo.BlockBits / 8);
                Log.WriteBytes("IV", iv);

                var cipherAlg = this.cipherInfo.GetAlg();
                using (cipherAlg)
                {
                    ICryptoTransform transform = null;
                    if (isEncryption)
                        transform = cipherAlg.CreateEncryptor(secretKey, iv);
                    else
                        transform = cipherAlg.CreateDecryptor(secretKey, iv);

                    Log.PopScope();
                    return transform;
                }
            }
        }

        internal void Save(PasswordKeyEncryptorConfig config, PasswordKeyEncryptorData data)
        {
            config.CipherConfig = this.cipherInfo.Copy();
            config.HashConfig = this.hashInfo.Copy();
            config.SaltSize = this.saltValue.Length;
            config.SpinCount = this.spinCount;

            data.SaltValue = (byte[])this.SaltValue.Clone();
        }
    }
}
