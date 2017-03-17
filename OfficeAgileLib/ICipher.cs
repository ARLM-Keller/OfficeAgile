using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Simple interface to abstract the types of encryption
    /// </summary>
    public interface ICipherProvider
    {
        int BlockBytes { get; }

        ICryptoTransform GetCryptoTransform(byte[] blockKey, bool isEncryption);
    }
}
