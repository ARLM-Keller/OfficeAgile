using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// This class handles encrypting the secret key with a password-derived key
    /// </summary>
    class PasswordKeyEncryptor
    {
        private static readonly byte[] hashInputBlockKey = new byte[] { 0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79, };
        private static readonly byte[] hashValueBlockKey = new byte[] { 0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e, };
        private static readonly byte[] secretKeyBlockKey = new byte[] { 0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6, };

        private byte[] encryptedHashInput;
        private byte[] encryptedHashValue;
        private byte[] encryptedSecretKey;
        private PasswordBasedKey passwordEncryptor;

        internal byte[] EncryptedHashInput { get { return encryptedHashInput; } }
        internal byte[] EncryptedHashValue { get { return encryptedHashValue; } }
        internal byte[] EncryptedSecretKey { get { return encryptedSecretKey; } }
        internal PasswordBasedKey PasswordEncryptor { get { return passwordEncryptor; } }

        /// <summary>
        /// Create a new PasswordKeyEncryptor
        /// </summary>
        /// <param name="config"></param>
        public PasswordKeyEncryptor(PasswordKeyEncryptorConfig config)
        {
            this.passwordEncryptor = new PasswordBasedKey(config);
        }

        /// <summary>
        /// Load an existing PasswordKeyEncryptor
        /// </summary>
        /// <param name="config"></param>
        /// <param name="data"></param>
        public PasswordKeyEncryptor(PasswordKeyEncryptorConfig config, PasswordKeyEncryptorData data)
        {
            this.passwordEncryptor = new PasswordBasedKey(config, data);
            this.encryptedHashInput = (byte[])data.EncryptedHashInput.Clone();
            this.encryptedHashValue = (byte[])data.EncryptedHashValue.Clone();
            this.encryptedSecretKey = (byte[])data.EncryptedKeyValue.Clone();
        }

        /// <summary>
        /// Create a new set of random data for the verifier hash input, and encrypt it
        /// </summary>
        /// <param name="passwordEncryptor"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] CreateEncryptedHashInput(PasswordBasedKey passwordEncryptor, string password)
        {
            Log.PushScope("PasswordKeyEncryptor::CreateEncryptedHashInput");

            // Create a new hash input
            var encryptedHashInput = new byte[Utils.RoundUp(passwordEncryptor.SaltValue.Length, passwordEncryptor.BlockBytes)];
            RandomNumberGenerator.Create().GetBytes(encryptedHashInput);
            Log.WriteBytes("PlaintextHashInput", encryptedHashInput);

            var encryptor = passwordEncryptor.GetEncryptor(hashValueBlockKey);
            using (encryptor)
            {
                encryptor.TransformInPlace(encryptedHashInput, 0, encryptedHashInput.Length);
                Log.WriteBytes("EncryptedHashInput", encryptedHashInput);
            }

            Log.PopScope();
            return encryptedHashInput;
        }

        /// <summary>
        /// Creates a password verifier
        ///     Decrypt encrypted hash input
        ///     Hash it
        ///     Encrypt hash value
        /// </summary>
        /// <param name="passwordEncryptor"></param>
        /// <param name="encryptedHashInput"></param>
        /// <returns>encrypted hash output</returns>
        public static byte[] CreateVerifier(PasswordBasedKey passwordEncryptor, byte[] encryptedHashInput)
        {
            Log.PushScope("PasswordKeyEncryptor::CreateVerifier");

            byte[] decryptedHashInput = (byte[])encryptedHashInput.Clone();
            var decryptor = passwordEncryptor.GetDecryptor(hashInputBlockKey);
            using (decryptor)
            {
                Log.WriteBytes("EncryptedHashInput", decryptedHashInput);
                decryptor.TransformInPlace(decryptedHashInput, 0, decryptedHashInput.Length);
                Log.WriteBytes("PlaintextHashInput", decryptedHashInput);
            }

            byte[] encryptedHashValue;
            var hashAlg = passwordEncryptor.GetHashAlg();
            using (hashAlg)
            {
                int hashValueBytes = hashAlg.HashSize / 8;
                encryptedHashValue = new byte[Utils.RoundUp(hashValueBytes, passwordEncryptor.BlockBytes)];
                hashAlg.TransformFinalBlock(decryptedHashInput, 0, decryptedHashInput.Length);
                Buffer.BlockCopy(hashAlg.Hash, 0, encryptedHashValue, 0, hashValueBytes);
            }

            var encryptor = passwordEncryptor.GetEncryptor(hashValueBlockKey);
            using (encryptor)
            {
                Log.WriteBytes("PlaintextHashValue", encryptedHashValue);
                encryptor.TransformInPlace(encryptedHashValue, 0, encryptedHashValue.Length);
                Log.WriteBytes("EncryptedHashValue", encryptedHashValue);
            }

            Log.PopScope();
            return encryptedHashValue;
        }

        /// <summary>
        /// Use the password to create a new verifier and encrypt the secret key
        /// TODO: in general, it is a good idea to refresh the Salt when the pwd changes
        /// </summary>
        /// <param name="password"></param>
        /// <param name="secretKey"></param>
        public void SetPassword(string password, byte[] secretKey)
        {
            Log.PushScope("PasswordKeyEncryptor::SetPassword");

            this.passwordEncryptor.SetPassword(password);
            this.encryptedHashInput = CreateEncryptedHashInput(this.passwordEncryptor, password);
            this.encryptedHashValue = CreateVerifier(passwordEncryptor, this.encryptedHashInput);

            var newEncryptedSecretKey = (byte[])secretKey.Clone();
            var encryptor = this.passwordEncryptor.GetEncryptor(secretKeyBlockKey);
            using (encryptor)
            {
                Log.WriteBytes("PlaintextSecretKey", newEncryptedSecretKey);
                encryptor.TransformInPlace(newEncryptedSecretKey, 0, newEncryptedSecretKey.Length);
                Log.WriteBytes("EncryptedSecretKey", newEncryptedSecretKey);
            }

            this.encryptedSecretKey = newEncryptedSecretKey;

            Log.PopScope();
        }

        /// <summary>
        /// Try to unlock an existing secret key using the password
        /// </summary>
        /// <param name="password"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public bool TryUnlock(string password, out byte[] secretKey)
        {
            secretKey = null;
            if (this.encryptedHashInput == null || this.encryptedHashValue == null)
                throw new InvalidOperationException("No encrypted verifier");
            if (this.encryptedSecretKey == null)
                throw new InvalidOperationException("No encrypted secret to unlock");

            Log.PushScope("PasswordKeyEncryptor::TryUnlock");

            this.passwordEncryptor.SetPassword(password);

            var encryptedHashValueNew = CreateVerifier(passwordEncryptor, this.encryptedHashInput);
            if (!encryptedHashValueNew.EqualBytes(this.encryptedHashValue))
            {
                Log.WriteLine("Incorrect password");
                Log.PopScope();
                return false;
            }

            var decryptedSecretKey = (byte[])this.encryptedSecretKey.Clone();
            var decryptor = this.passwordEncryptor.GetDecryptor(secretKeyBlockKey);
            using (decryptor)
            {
                Log.WriteBytes("EncryptedSecretKey", decryptedSecretKey);
                decryptor.TransformInPlace(decryptedSecretKey, 0, decryptedSecretKey.Length);
                Log.WriteBytes("PlaintextSecretKey", decryptedSecretKey);
            }
            secretKey = decryptedSecretKey;

            Log.WriteLine("Correct password");
            Log.PopScope();
            return true;
        }

        /// <summary>
        /// Copy the relevant config + data information
        /// </summary>
        /// <param name="config"></param>
        /// <param name="data"></param>
        internal void Save(PasswordKeyEncryptorConfig config, PasswordKeyEncryptorData data)
        {
            this.passwordEncryptor.Save(config, data);
            data.EncryptedHashInput = (byte[])this.encryptedHashInput.Clone();
            data.EncryptedHashValue = (byte[])this.encryptedHashValue.Clone();
            data.EncryptedKeyValue = (byte[])this.encryptedSecretKey.Clone();
        }
    }
}
