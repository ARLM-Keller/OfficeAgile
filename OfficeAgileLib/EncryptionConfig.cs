using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Xml;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Configuration class for the document encryption
    /// </summary>
    public class EncryptionConfig
    {
        public CipherConfig CipherConfig { get; set; }
        public HashConfig HashConfig { get; set; }
        public PasswordKeyEncryptorConfig PasswordKeyEncryptorConfig { get; set; }
        public int SaltSize { get; set; }

        public EncryptionConfig()
        {
        }
    }

    /// <summary>
    /// Configuration class for encryption
    /// </summary>
    public class CipherConfig
    {
        public int BlockBits { get; set; }
        public int KeyBits { get; set; }
        public string Name { get; set; }
        public string Mode { get; set; }

        public CipherConfig() { }
        public CipherConfig Copy() { return (CipherConfig)this.MemberwiseClone(); }

        /// <summary>
        /// Returns an Instance of the encryption alg
        /// </summary>
        /// <returns></returns>
        public SymmetricAlgorithm GetAlg()
        {
            var cipherAlg = SymmetricAlgorithm.Create(this.Name);
            cipherAlg.BlockSize = this.BlockBits;
            cipherAlg.KeySize = this.KeyBits;
            cipherAlg.Padding = PaddingMode.None;

            if (this.Mode == "ChainingModeCBC")
                cipherAlg.Mode = CipherMode.CBC;
            else if (this.Mode == "ChainingModeCFB")
                cipherAlg.Mode = CipherMode.CFB;
            else
                throw new InvalidDataException("Unexpected chaining mode");

            return cipherAlg;
        }
    }

    /// <summary>
    /// Configuration class for hashing
    /// </summary>
    public class HashConfig
    {
        public int HashBits { get; set; }
        public string Name { get; set; }

        public HashConfig() { }
        public HashConfig Copy() { return (HashConfig)this.MemberwiseClone(); }

        /// <summary>
        /// Returns an instance of the hash alg
        /// </summary>
        /// <returns></returns>
        public HashAlgorithm GetAlg()
        {
            HashAlgorithm hashAlg;

            // We switch over the possible names because, unfortunately, HashAlgorithm.Create
            // chooses to initialize the SHA***Managed() implementations for SHA 256, 284, and
            // 512. These implementations are not FIPS-compliant, therefore we explicitly
            // instantiate them.
            switch (Name)
            {
                case "SHA256": hashAlg = new SHA256CryptoServiceProvider();
                    break;
                case "SHA384": hashAlg = new SHA384CryptoServiceProvider();
                    break;
                case "SHA512": hashAlg = new SHA512CryptoServiceProvider();
                    break;
                default: hashAlg = HashAlgorithm.Create(this.Name);
                    break;
            }

            if (hashAlg.HashSize != this.HashBits)
                throw new InvalidDataException("Unexpected hash size");

            hashAlg.Initialize();
            return hashAlg;
        }
    }

    /// <summary>
    /// Configuration information for PasswordKeyEncryptor
    /// </summary>
    public class PasswordKeyEncryptorConfig
    {
        public HashConfig HashConfig { get; set; }
        public CipherConfig CipherConfig { get; set; }
        public int SaltSize { get; set; }
        public int SpinCount { get; set; }

        public PasswordKeyEncryptorConfig()
        {
        }
    }

    /// <summary>
    /// Data loaded from the file for an HMAC
    /// </summary>
    internal class HmacData
    {
        public byte[] EncryptedKey { get; set; }
        public byte[] EncryptedValue { get; set; }

        public HmacData() { }
        public HmacData Copy()
        {
            var copy = new HmacData();
            copy.EncryptedKey = (byte[])this.EncryptedKey.Clone();
            copy.EncryptedValue = (byte[])this.EncryptedValue.Clone();
            return copy;
        }
    }

    /// <summary>
    /// Data loaded from the file for document encryption
    /// </summary>
    internal class EncryptionData
    {
        private static string rootUri = "http://schemas.microsoft.com/office/2006/encryption";

        public byte[] SaltValue { get; set; }
        public HmacData HmacData { get; set; }
        public PasswordKeyEncryptorData PasswordEncryptorData { get; set; }

        public EncryptionData()
        {
        }

        public static EncryptionData LoadFromStream(Stream infoStream, out EncryptionConfig config)
        {
            return LoadFromStream(infoStream, true /*useHmac*/, out config);
        }

        public static EncryptionData LoadFromStream(Stream infoStream, bool useHmac, out EncryptionConfig config)
        {
            // Load the version - only support Agile
            int flag = infoStream.ReadInt16();
            if (flag != 4)
                throw new InvalidOperationException("Non-agile stream");

            // Load the version - only support Agile
            flag = infoStream.ReadInt16();
            if (flag != 4)
                throw new InvalidOperationException("Non-agile stream");

            // Load the flags
            flag = infoStream.ReadInt32();
            Debug.Assert(flag == 0x40);

            // Load the remaining content as Xml
            var reader = new XmlTextReader(infoStream);
            using (reader)
            {
                return LoadFromXml(reader, useHmac, out config);
            }
        }

        /// <summary>
        /// Load the entire EncryptionInfo XML into the config + data classes
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="useHmac"></param>
        /// <param name="configOut"></param>
        /// <returns></returns>
        private static EncryptionData LoadFromXml(XmlTextReader reader, bool useHmac, out EncryptionConfig configOut)
        {
            var config = new EncryptionConfig();
            config.CipherConfig = new CipherConfig();
            config.HashConfig = new HashConfig();

            var data = new EncryptionData();
            data.HmacData = new HmacData();

            // <Encryption>
            reader.MoveToStartElement(rootUri, "encryption");
            reader.ParseAttributes(0, (NameToken nameToken, String value) => { return false; });

            // <keyData>
            reader.MoveToStartElement(rootUri, "keyData");
            reader.ParseAttributes(8, (NameToken nameToken, String value) =>
            {
                switch (nameToken)
                {
                    case NameToken.blockSize:
                        config.CipherConfig.BlockBits = Int32.Parse(value) * 8;
                        return true;
                    case NameToken.keyBits:
                        config.CipherConfig.KeyBits = Int32.Parse(value);
                        return true;
                    case NameToken.hashSize:
                        config.HashConfig.HashBits = Int32.Parse(value) * 8;
                        return true;
                    case NameToken.cipherAlgorithm:
                        config.CipherConfig.Name = value;
                        return true;
                    case NameToken.cipherChaining:
                        config.CipherConfig.Mode = value;
                        return true;
                    case NameToken.hashAlgorithm:
                        config.HashConfig.Name = value;
                        return true;
                    case NameToken.saltSize:
                        config.SaltSize = Int32.Parse(value);
                        return true;
                    case NameToken.saltValue:
                        data.SaltValue = Convert.FromBase64String(value);
                        return true;
                }

                return false;
            });
            if (config.SaltSize != data.SaltValue.Length)
                throw new InvalidDataException("Invalid salt size/data found");
            reader.MoveToEndElement();

            // <dataIntegrity>
            if (useHmac)
            {
                reader.MoveToStartElement(rootUri, "dataIntegrity");
                reader.ParseAttributes(2, (NameToken nameToken, String value) =>
                {
                    switch (nameToken)
                    {
                        case NameToken.encryptedHmacKey:
                            data.HmacData.EncryptedKey = Convert.FromBase64String(value);
                            return true;
                        case NameToken.encryptedHmacValue:
                            data.HmacData.EncryptedValue = Convert.FromBase64String(value);
                            return true;
                    }

                    return false;
                });
                reader.MoveToEndElement();
            }

            // <keyEncryptors>
            reader.MoveToStartElement(rootUri, "keyEncryptors");
            reader.ParseAttributes(0, (NameToken nameToken, String value) => { return false; });

            // <keyEncryptor>
            reader.MoveToStartElement(rootUri, "keyEncryptor");
            while (true)
            {
                // keyEncryptor attributes
                string encryptorUri = String.Empty;
                reader.ParseAttributes(1, (NameToken nameToken, String value) =>
                {
                    if (nameToken == NameToken.uri)
                    {
                        encryptorUri = value;
                        return true;
                    }

                    return false;
                });
                if (encryptorUri.Length == 0)
                    throw new InvalidDataException("Found empty Uri");

                if (encryptorUri == PasswordKeyEncryptorData.RootUri)
                {
                    PasswordKeyEncryptorConfig passwordKeyEncryptorConfig;
                    data.PasswordEncryptorData = PasswordKeyEncryptorData.LoadFromXml(reader, out passwordKeyEncryptorConfig);
                    config.PasswordKeyEncryptorConfig = passwordKeyEncryptorConfig;
                }
                else
                {
                    string xmlNamespaceUri = reader.NamespaceURI;
                    // Unknown encryptor, just move to the content
                    while (true)
                    {
                        reader.MoveToNextContent();
                        if (reader.NodeType == XmlNodeType.EndElement && reader.Name == "keyEncryptor" && reader.NamespaceURI == xmlNamespaceUri)
                            break;
                    }

                    //TODO: round-trip unknown encryptor xml
                }

                Debug.Assert(reader.NodeType == XmlNodeType.EndElement);
                Debug.Assert(reader.Name == "keyEncryptor");
                reader.MoveToNextContent();

                if (reader.NodeType == XmlNodeType.EndElement)
                    break;
            }
            Debug.Assert(reader.NodeType == XmlNodeType.EndElement);
            Debug.Assert(reader.Name == "keyEncryptors");
            reader.MoveToNextContent();

            Debug.Assert(reader.NodeType == XmlNodeType.EndElement);
            Debug.Assert(reader.Name == "encryption");

            // All done
            configOut = config;
            return data;
        }

        /// <summary>
        /// Write the given config + data classes into the EncryptionInfo stream
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="config"></param>
        /// <param name="data"></param>
        public static void WriteToStream(Stream stream, EncryptionConfig config, EncryptionData data)
        {
            // Write version, version, and flags
            stream.WriteInt16(4);
            stream.WriteInt16(4);
            stream.WriteInt32(0x40);

            // Generate the crypto xml
            var writer = new XmlTextWriter(stream, Encoding.UTF8);
            using (writer)
            {
                WriteToXml(writer, config, data);
            }
        }

        /// <summary>
        /// Write the given config + data classes into XML
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="config"></param>
        /// <param name="data"></param>
        public static void WriteToXml(XmlTextWriter writer, EncryptionConfig config, EncryptionData data)
        {
            writer.WriteStartDocument();

            // <encryption>
            writer.WriteStartElement("encryption", rootUri);

            // <keyData>
            writer.WriteStartElement("keyData", rootUri);
            writer.WriteAttributeString(NameToken.blockSize.ToString(), (config.CipherConfig.BlockBits / 8).ToString());
            writer.WriteAttributeString(NameToken.saltSize.ToString(), config.SaltSize.ToString());
            writer.WriteAttributeString(NameToken.keyBits.ToString(), config.CipherConfig.KeyBits.ToString());
            writer.WriteAttributeString(NameToken.hashSize.ToString(), (config.HashConfig.HashBits / 8).ToString());
            writer.WriteAttributeString(NameToken.cipherAlgorithm.ToString(), config.CipherConfig.Name);
            writer.WriteAttributeString(NameToken.cipherChaining.ToString(), config.CipherConfig.Mode);
            writer.WriteAttributeString(NameToken.hashAlgorithm.ToString(), config.HashConfig.Name);
            writer.WriteAttributeString(NameToken.saltValue.ToString(), Convert.ToBase64String(data.SaltValue, Base64FormattingOptions.None));
            writer.WriteEndElement();
            // </keyData>

            if (data.HmacData != null)
            {
                // <dataIntegrity>
                writer.WriteStartElement("dataIntegrity", rootUri);
                writer.WriteAttributeString(NameToken.encryptedHmacKey.ToString(), Convert.ToBase64String(data.HmacData.EncryptedKey, Base64FormattingOptions.None));
                writer.WriteAttributeString(NameToken.encryptedHmacValue.ToString(), Convert.ToBase64String(data.HmacData.EncryptedValue, Base64FormattingOptions.None));
                writer.WriteEndElement();
                // </dataIntegrity>
            }


            // <keyEncryptors>
            writer.WriteStartElement("keyEncryptors", rootUri);
            {
                // <keyEncryptor>
                writer.WriteStartElement("keyEncryptor", rootUri);
                writer.WriteAttributeString(NameToken.uri.ToString(), PasswordKeyEncryptorData.RootUri);
                {
                    PasswordKeyEncryptorData.WriteToXml(writer, config.PasswordKeyEncryptorConfig, data.PasswordEncryptorData);
                }
                writer.WriteEndElement();
                // </keyEncryptor>
            }
            writer.WriteEndElement();
            // </keyEncryptors>

            writer.WriteEndElement();
            // </encryption>

            writer.WriteEndDocument();
            writer.Flush();
        }
    }

    /// <summary>
    /// Data for a PasswordKeyEncryptor
    /// </summary>
    internal class PasswordKeyEncryptorData
    {
        private static string rootUri = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
        public static string RootUri { get { return rootUri; } }

        public byte[] EncryptedHashInput { get; set; }
        public byte[] EncryptedHashValue { get; set; }
        public byte[] EncryptedKeyValue { get; set; }
        public byte[] SaltValue { get; set; }
        public byte[] SecretKey { get; set; }

        public PasswordKeyEncryptorData() { }

        /// <summary>
        /// Loads the config + data from XML
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="configOut"></param>
        /// <returns></returns>
        internal static PasswordKeyEncryptorData LoadFromXml(XmlTextReader reader, out PasswordKeyEncryptorConfig configOut)
        {
            var data = new PasswordKeyEncryptorData();

            var config = new PasswordKeyEncryptorConfig();
            config.CipherConfig = new CipherConfig();
            config.HashConfig = new HashConfig();

            // <p:encryptedKey>
            reader.MoveToStartElement(rootUri, "encryptedKey");
            reader.ParseAttributes(12, (NameToken nameToken, String value) =>
            {
                switch (nameToken)
                {
                    case NameToken.spinCount:
                        config.SpinCount = Int32.Parse(value);
                        return true;
                    case NameToken.saltSize:
                        config.SaltSize = Int32.Parse(value);
                        return true;
                    case NameToken.blockSize:
                        config.CipherConfig.BlockBits = Int32.Parse(value) * 8;
                        return true;
                    case NameToken.keyBits:
                        config.CipherConfig.KeyBits = Int32.Parse(value);
                        return true;
                    case NameToken.hashSize:
                        config.HashConfig.HashBits = Int32.Parse(value) * 8;
                        return true;
                    case NameToken.cipherAlgorithm:
                        config.CipherConfig.Name = value;
                        return true;
                    case NameToken.cipherChaining:
                        config.CipherConfig.Mode = value;
                        return true;
                    case NameToken.hashAlgorithm:
                        config.HashConfig.Name = value;
                        return true;
                    case NameToken.saltValue:
                        data.SaltValue = Convert.FromBase64String(value);
                        return true;
                    case NameToken.encryptedVerifierHashInput:
                        data.EncryptedHashInput = Convert.FromBase64String(value);
                        return true;
                    case NameToken.encryptedVerifierHashValue:
                        data.EncryptedHashValue = Convert.FromBase64String(value);
                        return true;
                    case NameToken.encryptedKeyValue:
                        data.EncryptedKeyValue = Convert.FromBase64String(value);
                        return true;
                }

                return false;
            });
            if (config.SaltSize != data.SaltValue.Length)
                throw new InvalidDataException("Invalid salt size/data found");

            // Move off of the key encryptor
            if (!reader.IsEmptyElement)
                reader.MoveToNextContent();
            reader.MoveToNextContent();

            configOut = config;
            return data;
        }

        /// <summary>
        /// Writes the config + data into XML
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="config"></param>
        /// <param name="data"></param>
        public static void WriteToXml(XmlTextWriter writer, PasswordKeyEncryptorConfig config, PasswordKeyEncryptorData data)
        {
            // <p:encryptedKey>
            writer.WriteStartElement("encryptedKey", rootUri);
            writer.WriteAttributeString(NameToken.spinCount.ToString(), config.SpinCount.ToString());
            writer.WriteAttributeString(NameToken.saltSize.ToString(), config.SaltSize.ToString());
            writer.WriteAttributeString(NameToken.blockSize.ToString(), (config.CipherConfig.BlockBits / 8).ToString());
            writer.WriteAttributeString(NameToken.keyBits.ToString(), config.CipherConfig.KeyBits.ToString());
            writer.WriteAttributeString(NameToken.cipherAlgorithm.ToString(), config.CipherConfig.Name);
            writer.WriteAttributeString(NameToken.cipherChaining.ToString(), config.CipherConfig.Mode);
            writer.WriteAttributeString(NameToken.hashAlgorithm.ToString(), config.HashConfig.Name);
            writer.WriteAttributeString(NameToken.hashSize.ToString(), (config.HashConfig.HashBits / 8).ToString());
            writer.WriteAttributeString(NameToken.saltValue.ToString(), Convert.ToBase64String(data.SaltValue, Base64FormattingOptions.None));
            writer.WriteAttributeString(NameToken.encryptedVerifierHashInput.ToString(), Convert.ToBase64String(data.EncryptedHashInput, Base64FormattingOptions.None));
            writer.WriteAttributeString(NameToken.encryptedVerifierHashValue.ToString(), Convert.ToBase64String(data.EncryptedHashValue, Base64FormattingOptions.None));
            writer.WriteAttributeString(NameToken.encryptedKeyValue.ToString(), Convert.ToBase64String(data.EncryptedKeyValue, Base64FormattingOptions.None));
            writer.WriteEndElement();
            // </p:encryptedKey>
        }
    }

    /// <summary>
    /// Inefficient way to tokenize XML names
    /// </summary>
    enum NameToken
    {
        blockSize,
        keyBits,
        hashSize,
        saltSize,
        saltValue,
        cipherAlgorithm,
        cipherChaining,
        hashAlgorithm,
        encryptedHmacKey,
        encryptedHmacValue,
        uri,
        spinCount,
        encryptedVerifierHashInput,
        encryptedVerifierHashValue,
        encryptedKeyValue,
    }
}

