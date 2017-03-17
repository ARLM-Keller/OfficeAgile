using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Contains a set of functions related to HMAC
    /// </summary>
    static class Hmac
    {
        private static readonly byte[] hmacSaltBlockKey = { 0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6, };
        private static readonly byte[] hmacValueBlockKey = { 0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33, };

        /// <summary>
        /// Generate a new HMAC for the given stream and encrypt the key + result
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="hashInfo"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static HmacData GetHmac(ICipherProvider cipher, HashConfig hashInfo, Stream stream)
        {
            Log.PushScope("Hmac::GetHmac");

            var hmacKey = new byte[hashInfo.HashBits / 8];
            RandomNumberGenerator.Create().GetBytes(hmacKey);
            hmacKey = hmacKey.CloneToFit(Utils.RoundUp(hmacKey.Length, cipher.BlockBytes), 0);
            Log.WriteBytes("HmacKey", hmacKey);

            var hmac = HMAC.Create();
            hmac.HashName = hashInfo.Name;
            hmac.Key = hmacKey;
            hmac.Initialize();

            stream.Position = 0;
            var hmacValue = hmac.ComputeHash(stream);
            hmacValue = hmacValue.CloneToFit(Utils.RoundUp(hmacValue.Length, cipher.BlockBytes), 0);
            Log.WriteBytes("HmacValue", hmacValue);

            var encryptor = cipher.GetEncryptor(hmacSaltBlockKey);
            using (encryptor)
            {
                encryptor.TransformInPlace(hmacKey, 0, hmacKey.Length);
                Log.WriteBytes("EncryptedHmacKey", hmacKey);
            }

            encryptor = cipher.GetEncryptor(hmacValueBlockKey);
            using (encryptor)
            {
                encryptor.TransformInPlace(hmacValue, 0, hmacValue.Length);
                Log.WriteBytes("EncryptedHmacValue", hmacValue);
            }

            var hmacInfo = new HmacData();
            hmacInfo.EncryptedKey = hmacKey;
            hmacInfo.EncryptedValue = hmacValue;

            Log.PopScope();
            return hmacInfo;
        }

        /// <summary>
        /// Check the HMAC for a given stream
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="hashInfo"></param>
        /// <param name="hmacInfo"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static bool CheckStream(ICipherProvider cipher, HashConfig hashInfo, HmacData hmacInfo, Stream stream)
        {
            Log.PushScope("Hmac::CheckStream");

            var decryptedKey = (byte[])hmacInfo.EncryptedKey.Clone();
            var decryptor = cipher.GetDecryptor(hmacSaltBlockKey);
            using (decryptor)
            {
                Log.WriteBytes("EncryptedHmacKey", decryptedKey);
                decryptor.TransformInPlace(decryptedKey, 0, decryptedKey.Length);
                Log.WriteBytes("PlaintextHmacKey", decryptedKey);
            }

            var decryptedValue = (byte[])hmacInfo.EncryptedValue.Clone();
            decryptor = cipher.GetDecryptor(hmacValueBlockKey);
            using (decryptor)
            {
                Log.WriteBytes("EncryptedHmacValue", decryptedValue);
                decryptor.TransformInPlace(decryptedValue, 0, decryptedValue.Length);
                Log.WriteBytes("PlaintextHmacValue", decryptedValue);
            }

            // All zeroes indicates that the HMAC is not enabled
            if (decryptedKey.All(b => b == 0) && decryptedValue.All(b => b == 0))
            {
                Log.WriteLine("HMAC disabled: contains all zeros");
                Log.PopScope();
                return true;
            }

            var hmacKey = new byte[hashInfo.HashBits / 8];
            Buffer.BlockCopy(decryptedKey, 0, hmacKey, 0, hmacKey.Length);
            for (int i = hmacKey.Length; i < decryptedKey.Length; i++)
            {
                if (decryptedKey[i] != 0)
                {
                    Log.WriteLine("HMAC padding must be all zero");
                    Log.PopScope();
                    return false;
                }
            }

            var hmac = HMAC.Create();
            hmac.HashName = hashInfo.Name;
            hmac.Key = hmacKey;
            hmac.Initialize();

            var hmacValue = new byte[hashInfo.HashBits / 8];
            Buffer.BlockCopy(decryptedValue, 0, hmacValue, 0, hmacValue.Length);
            for (int i = decryptedValue.Length; i < decryptedValue.Length; i++)
            {
                // The padding should be all zero
                if (decryptedValue[i] != 0)
                {
                    Log.WriteLine("HMAC padding must be all zero");
                    Log.PopScope();
                    return false;
                }
            }

            var actualHmacValue = hmac.ComputeHash(stream);
            bool isValid = actualHmacValue.EqualBytes(hmacValue);

            Log.PopScope();
            return isValid;
        }
    }
}
