using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Xml;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Microsoft.Office.Crypto.Agile
{
    public static class Utils
    {
        /// <summary>
        /// Read a given number of bytes and fail if not all present
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bytesToRead"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(Stream stream, int bytesToRead)
        {
            var buffer = new byte[bytesToRead];
            if (stream.Read(buffer, 0, buffer.Length) != bytesToRead)
                throw new InvalidDataException("Not enough stream data");

            return buffer;
        }

        /// <summary>
        /// Read an Int16
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static Int16 ReadInt16(this Stream stream)
        {
            return BitConverter.ToInt16(ReadBytes(stream, sizeof(Int16)), 0);
        }

        /// <summary>
        /// Read an Int32
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static Int32 ReadInt32(this Stream stream)
        {
            return BitConverter.ToInt32(ReadBytes(stream, sizeof(Int32)), 0);
        }

        /// <summary>
        /// Read an Int64
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static Int64 ReadInt64(this Stream stream)
        {
            return BitConverter.ToInt64(ReadBytes(stream, sizeof(Int64)), 0);
        }

        /// <summary>
        /// Write an Int16
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        public static void WriteInt16(this Stream stream, Int16 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int16));
        }

        /// <summary>
        /// Write an Int32
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        public static void WriteInt32(this Stream stream, Int32 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int32));
        }

        /// <summary>
        /// Write an Int64
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        public static void WriteInt64(this Stream stream, Int64 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int64));
        }

        /// <summary>
        /// Round an int up to the next 'round' boundary
        /// </summary>
        /// <param name="value"></param>
        /// <param name="round"></param>
        /// <returns></returns>
        public static int RoundUp(int value, int round)
        {
            if (round == 0)
                return round;
            return ((value + round - 1) / round) * round;
        }

        /// <summary>
        /// Return a copy of the array, sized to fit
        /// </summary>
        /// <param name="input"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public static byte[] CloneToFit(this byte[] input, int size)
        {
            return input.CloneToFit(size, 0x36);
        }

        /// <summary>
        /// Return a copy of the array, sized to fit
        /// </summary>
        /// <param name="input"></param>
        /// <param name="size"></param>
        /// <param name="pad"></param>
        /// <returns></returns>
        public static byte[] CloneToFit(this byte[] input, int size, byte pad)
        {
            var output = new byte[size];
            Buffer.BlockCopy(input, 0, output, 0, Math.Min(input.Length, output.Length));
            for (int i = input.Length; i < output.Length; i++)
                output[i] = pad;

            return output;
        }

        /// <summary>
        /// ICipher extension around GetCryptoTransform
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="key1"></param>
        /// <param name="key2"></param>
        /// <param name="isEncryption"></param>
        /// <returns></returns>
        public static ICryptoTransform GetCryptoTransform(this ICipherProvider cipher, int key1, int key2, bool isEncryption)
        {
            if (key2 == 0)
            {
                return cipher.GetCryptoTransform(BitConverter.GetBytes(key1), isEncryption);
            }
            else
            {
                byte[] blockKey = new byte[8];
                Buffer.BlockCopy(BitConverter.GetBytes(key2), 0, blockKey, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(key1), 0, blockKey, 4, 4);
                return cipher.GetCryptoTransform(blockKey, isEncryption);
            }
        }

        /// <summary>
        /// Get an Encryption object
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="key1"></param>
        /// <param name="key2"></param>
        /// <returns></returns>
        public static ICryptoTransform GetEncryptor(this ICipherProvider cipher, int key1, int key2)
        {
            return cipher.GetCryptoTransform(key1, key2, true);
        }

        /// <summary>
        /// Get an Encryption object
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="blockKey"></param>
        /// <returns></returns>
        public static ICryptoTransform GetEncryptor(this ICipherProvider cipher, byte[] blockKey)
        {
            return cipher.GetCryptoTransform(blockKey, true);
        }

        /// <summary>
        /// Get an Decryption object
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="key1"></param>
        /// <param name="key2"></param>
        /// <returns></returns>
        public static ICryptoTransform GetDecryptor(this ICipherProvider cipher, int key1, int key2)
        {
            return cipher.GetCryptoTransform(key1, key2, false);
        }

        /// <summary>
        /// Get an Decryption object
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="blockKey"></param>
        /// <returns></returns>
        public static ICryptoTransform GetDecryptor(this ICipherProvider cipher, byte[] blockKey)
        {
            return cipher.GetCryptoTransform(blockKey, false);
        }

        /// <summary>
        /// Perform the crypto operation in-place
        /// </summary>
        /// <param name="transform"></param>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public static void TransformInPlace(this ICryptoTransform transform, byte[] buffer, int offset, int count)
        {
            if (count == 0)
                return;

            Debug.Assert((count % transform.InputBlockSize) == 0);
            Debug.Assert(transform.InputBlockSize == transform.OutputBlockSize);
            int outputCount = transform.TransformBlock(buffer, offset, count, buffer, offset);
            if (count != outputCount)
                throw new InvalidDataException();
        }

        /// <summary>
        /// Are two arrays equal?
        /// </summary>
        /// <param name="arr1"></param>
        /// <param name="arr2"></param>
        /// <returns></returns>
        public static bool EqualBytes(this byte[] arr1, byte[] arr2)
        {
            // REVIEW: use IStructuralEquatable in .Net 4.0?
            if (arr1.Length != arr2.Length)
                return false;

            for (int i = 0; i < arr1.Length; i++)
            {
                if (arr1[i] != arr2[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Validate the current node state
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="namespaceUri"></param>
        /// <param name="localName"></param>
        internal static void CheckNode(this XmlTextReader reader, string namespaceUri, string localName)
        {
            if (reader.LocalName != localName)
                throw new InvalidDataException();
            if (reader.NamespaceURI != namespaceUri)
                throw new InvalidDataException();
        }

        /// <summary>
        /// Move to the next piece of Content, and check if it's an Element
        /// </summary>
        /// <param name="reader"></param>
        internal static void MoveToStartElement(this XmlTextReader reader)
        {
            reader.MoveToNextContent();
            if (reader.NodeType != XmlNodeType.Element)
                throw new InvalidDataException();
        }

        /// <summary>
        /// Move to the next piece of Content
        /// </summary>
        /// <param name="reader"></param>
        internal static void MoveToNextContent(this XmlTextReader reader)
        {
            if (!reader.Read())
                throw new InvalidDataException();
            reader.MoveToContent();
        }

        /// <summary>
        /// Position the reader on the next startElement
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="namespaceUri"></param>
        /// <param name="localName"></param>
        internal static void MoveToStartElement(this XmlTextReader reader, string namespaceUri, string localName)
        {
            reader.MoveToStartElement();
            reader.CheckNode(namespaceUri, localName);
        }

        /// <summary>
        /// Position the reader on the next endElement, or remain on the start element if Empty
        /// </summary>
        /// <param name="reader"></param>
        internal static void MoveToEndElement(this XmlTextReader reader)
        {
            if (!reader.IsEmptyElement)
            {
                reader.MoveToNextContent();

                if (reader.NodeType != XmlNodeType.EndElement)
                    throw new InvalidDataException();
            }
        }

        /// <summary>
        /// Converts each attribute into a Token, and invokes the Action
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="attributeMax"></param>
        /// <param name="action"></param>
        internal static void ParseAttributes(this XmlTextReader reader, int attributeMax, Func<NameToken, String, bool> action)
        {
            int attributeCount = 0;
            if (reader.MoveToFirstAttribute())
            {
                do
                {
                    if (reader.IsXmlnsAttribute())
                        continue;

                    NameToken nameToken;
                    if (!Enum.TryParse(reader.LocalName, out nameToken))
                        throw new InvalidDataException();
                    if (reader.NamespaceURI.Length != 0)
                        throw new InvalidDataException();
                    if (!action(nameToken, reader.Value))
                        throw new InvalidDataException();

                    attributeCount++;
                } while (reader.MoveToNextAttribute());
            }

            if (attributeCount != attributeMax)
                throw new InvalidDataException();
            reader.MoveToElement();
        }

        /// <summary>
        /// Checks if the current attribute is an xmlns attribute
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static bool IsXmlnsAttribute(this XmlTextReader reader)
        {
            if (reader.NodeType != XmlNodeType.Attribute)
                return false;
            if (reader.Prefix == "xmlns")
                return true;
            if (reader.Prefix.Length == 0 && reader.LocalName == "xmlns")
                return true;
            return false;
        }

        /// <summary>
        /// Copies a file into the given stream
        /// </summary>
        /// <param name="outStream"></param>
        /// <param name="file"></param>
        public static void CopyFromFile(this Stream outStream, string file)
        {
            var inStream = File.Open(file, FileMode.Open, FileAccess.Read);
            using (inStream)
            {
                inStream.CopyTo(outStream);
            }
        }

        /// <summary>
        /// Copies a stream into the given file
        /// </summary>
        /// <param name="inStream"></param>
        /// <param name="file"></param>
        public static void CopyToFile(this Stream inStream, string file)
        {
            var outStream = File.Open(file, FileMode.Create, FileAccess.Write);
            using (outStream)
            {
                inStream.CopyTo(outStream);
            }
        }
    }
}
