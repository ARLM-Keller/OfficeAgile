using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Microsoft.Office.Crypto.Agile
{
    /// <summary>
    /// Stream wrapper class that manages the encryption/decryption for the main stream
    /// Assumes that the plaintext length == ciphertext length
    /// Uses a 4k window to manage the current content block
    /// </summary>
    public class EncryptedStream : Stream
    {
        private ICipherProvider cipher;
        private Stream dataStream;
        private byte[] contentBuffer = new byte[4096];
        private long contentPosition = 0;
        private long contentLength = 0;
        private bool isLengthDirty = false;
        private bool isBufferDirty = false;

        public override bool CanRead { get { return this.dataStream.CanRead; } }
        public override bool CanSeek { get { return this.dataStream.CanSeek; } }
        public override bool CanWrite { get { return this.dataStream.CanWrite; } }
        public override long Length { get { return this.contentLength; } }
        public override long Position { get { return this.contentPosition; } set { MoveToOffset(value, false); } }

        public EncryptedStream(ICipherProvider cipher, Stream dataStream)
        {
            this.cipher = cipher;
            this.dataStream = dataStream;

            if (dataStream.Length > 0)
            {
                dataStream.Position = 0;
                this.contentLength = dataStream.ReadInt64();
                this.MoveToOffset(0, true);
            }
        }

        public override void SetLength(long value)
        {
            long streamSize = ToRealOffset(RoundToBlock(value));
            this.dataStream.SetLength(streamSize);
            SetContentLength(value);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (origin == SeekOrigin.Begin)
            {
                return this.Position = offset;
            }

            if (origin == SeekOrigin.Current)
            {
                return this.Position += offset;
            }

            if (origin == SeekOrigin.End)
            {
                return this.Position = this.Length + offset;
            }

            throw new ArgumentOutOfRangeException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int originalOffset = offset;

            long bytesRemaining = Math.Max(0, this.Length - this.Position);
            count = (int)Math.Min(count, bytesRemaining);

            int bufferOffset = (int)(this.Position % this.contentBuffer.Length);
            while (count > 0)
            {
                int bytesToRead = Math.Min(this.contentBuffer.Length - bufferOffset, count);
                Buffer.BlockCopy(this.contentBuffer, bufferOffset, buffer, offset, bytesToRead);

                this.MoveToOffset(this.Position + bytesToRead, false);

                offset += bytesToRead;
                count -= bytesToRead;
                bufferOffset = 0;
            }

            return (offset - originalOffset);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int bufferOffset = (int)(this.Position % this.contentBuffer.Length);
            while (count > 0)
            {
                int bytesToWrite = Math.Min(this.contentBuffer.Length - bufferOffset, count);
                Buffer.BlockCopy(buffer, offset, this.contentBuffer, bufferOffset, bytesToWrite);
                this.isBufferDirty = true;

                this.MoveToOffset(this.Position + bytesToWrite, false);

                offset += bytesToWrite;
                count -= bytesToWrite;
                bufferOffset = 0;
            }

            if (this.Position > this.Length)
                SetContentLength(this.Position);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Flush();

            base.Dispose(disposing);
        }

        public override void Flush()
        {
            if (this.isBufferDirty)
            {
                MoveToOffset(this.Position, true);
            }

            if (this.isLengthDirty)
            {
                if (this.Length > 0)
                {
                    long roundedLength = RoundToBlock(this.Length);
                    this.dataStream.SetLength(ToRealOffset(roundedLength));

                    this.dataStream.Position = 0;
                    this.dataStream.WriteInt64(this.Length);
                }
                else
                {
                    this.dataStream.SetLength(0);
                }

                this.isLengthDirty = false;
            }

            this.dataStream.Flush();
        }

        private void SetContentLength(long newLength)
        {
            if (this.Length != newLength)
            {
                this.isLengthDirty = true;
                this.contentLength = newLength;
            }
        }

        private long ToRealOffset(long offset)
        {
            return offset + sizeof(long);
        }

        private long RoundToBlock(long value)
        {
            return ((value + this.cipher.BlockBytes - 1) / this.cipher.BlockBytes) * this.cipher.BlockBytes;
        }

        private void MoveToOffset(long newPosition, bool forceRefresh)
        {
            long oldBlockIndex = this.Position / this.contentBuffer.Length;
            long newBlockIndex = newPosition / this.contentBuffer.Length;

            if (oldBlockIndex != newBlockIndex || forceRefresh)
            {
                if (this.isBufferDirty)
                {
                    // Encrypt the buffer
                    var encryptor = this.cipher.GetEncryptor((int)oldBlockIndex, 0);
                    using (encryptor)
                    {
                        encryptor.TransformInPlace(this.contentBuffer, 0, this.contentBuffer.Length);
                    }

                    // Write it into the underlying stream
                    this.dataStream.Position = ToRealOffset(oldBlockIndex * this.contentBuffer.Length);
                    this.dataStream.Write(this.contentBuffer, 0, this.contentBuffer.Length);

                    this.isBufferDirty = false;
                }

                this.dataStream.Position = ToRealOffset(newBlockIndex * this.contentBuffer.Length);
                int bytesRead = this.dataStream.Read(this.contentBuffer, 0, this.contentBuffer.Length);
                if (bytesRead < this.contentBuffer.Length)
                {
                    // Pad the rest of the buffer with random data
                    // REVIEW: this belongs in Commit
                    var paddingBytes = new byte[this.contentBuffer.Length - bytesRead];
                    RandomNumberGenerator.Create().GetBytes(paddingBytes);
                    Array.Copy(paddingBytes, 0, this.contentBuffer, bytesRead, paddingBytes.Length);
                }

                var decryptor = this.cipher.GetDecryptor((int)newBlockIndex, 0);
                using (decryptor)
                {
                    decryptor.TransformInPlace(this.contentBuffer, 0, bytesRead);
                }
            }

            this.contentPosition = newPosition;
        }

        private void FlushBuffer()
        {
            throw new NotImplementedException();
        }
    }
}
