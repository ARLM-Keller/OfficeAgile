using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Manages generating the IV and key for the main encryption/decryption
    /// </summary>
    internal class PrimaryCipher : ICipherProvider
    {
        private HashConfig hashInfo;
        private SymmetricAlgorithm cipherAlg;
        private byte[] secretKey;
        private byte[] saltValue;

        public byte[] SaltValue { get { return (byte[])saltValue.Clone(); } }
        public byte[] SecretKey { get { return (byte[])secretKey.Clone(); } }

        public PrimaryCipher(HashConfig hashInfo, CipherConfig cipherInfo, byte[] saltValue, byte[] secretKey)
        {
            this.hashInfo = hashInfo;
            this.cipherAlg = cipherInfo.GetAlg();
            this.secretKey = (byte[])secretKey.Clone();
            this.saltValue = (byte[])saltValue.Clone();
        }

        public int BlockBytes { get { return this.cipherAlg.BlockSize / 8; } }
        public HashAlgorithm GetHashAlg() { return this.hashInfo.GetAlg(); }

        public ICryptoTransform GetCryptoTransform(byte[] blockKey, bool isEncryption)
        {
            var hashAlg = this.GetHashAlg();
            hashAlg.TransformBlock(this.saltValue, 0, this.saltValue.Length, null, 0);
            hashAlg.TransformFinalBlock(blockKey, 0, blockKey.Length);
            var iv = hashAlg.Hash.CloneToFit(this.BlockBytes);

            if (isEncryption)
                return this.cipherAlg.CreateEncryptor(this.secretKey, iv);
            return this.cipherAlg.CreateDecryptor(this.secretKey, iv);
        }
    }
}
