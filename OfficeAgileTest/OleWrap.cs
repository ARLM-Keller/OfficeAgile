using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;

namespace Microsoft.Office.Crypto.Agile
{
    [ComImport]
    [Guid("0000000B-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage
    {
        void CreateStream(
            /* [string][in] */ string pwcsName,
            /* [in] */ uint grfMode,
            /* [in] */ uint reserved1,
            /* [in] */ uint reserved2,
            /* [out] */ out IStream ppstm);

        void OpenStream(
            /* [string][in] */ string pwcsName,
            /* [unique][in] */ IntPtr reserved1,
            /* [in] */ uint grfMode,
            /* [in] */ uint reserved2,
            /* [out] */ out IStream ppstm);

        void CreateStorage(
            /* [string][in] */ string pwcsName,
            /* [in] */ uint grfMode,
            /* [in] */ uint reserved1,
            /* [in] */ uint reserved2,
            /* [out] */ out IStorage ppstg);

        void OpenStorage(
            /* [string][unique][in] */ string pwcsName,
            /* [unique][in] */ IStorage pstgPriority,
            /* [in] */ uint grfMode,
            /* [unique][in] */ IntPtr snbExclude,
            /* [in] */ uint reserved,
            /* [out] */ out IStorage ppstg);

        void CopyTo(
            /* [in] */ uint ciidExclude,
            /* [size_is][unique][in] */ Guid rgiidExclude, // should this be an array?
            /* [unique][in] */ IntPtr snbExclude,
            /* [unique][in] */ IStorage pstgDest);

        void MoveElementTo(
            /* [string][in] */ string pwcsName,
            /* [unique][in] */ IStorage pstgDest,
            /* [string][in] */ string pwcsNewName,
            /* [in] */ uint grfFlags);

        void Commit(
            /* [in] */ uint grfCommitFlags);

        void Revert();

        void EnumElements(
            /* [in] */ uint reserved1,
            /* [size_is][unique][in] */ IntPtr reserved2,
            /* [in] */ uint reserved3,
            /* [out] */ out object ppenum);

        void DestroyElement(
            /* [string][in] */ string pwcsName);

        void RenameElement(
            /* [string][in] */ string pwcsOldName,
            /* [string][in] */ string pwcsNewName);

        void SetElementTimes(
            /* [string][unique][in] */ string pwcsName,
            /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME pctime,
            /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME patime,
            /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME pmtime);

        void SetClass(
            /* [in] */ Guid clsid);

        void SetStateBits(
            /* [in] */ uint grfStateBits,
            /* [in] */ uint grfMask);

        void Stat(
            /* [out] */ out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg,
            /* [in] */ uint grfStatFlag);

    }

    /// <summary>
    /// Simple Stream wrapper over IStream
    /// </summary>
    public class StreamOnIStream : Stream
    {
        private IStream istream;
        private byte[] tempBuffer = new byte[64 * 1024];

        public StreamOnIStream(IStream istream)
        {
            this.istream = istream;
        }

        ~StreamOnIStream()
        {
            Dispose(false /*disposing*/);
        }

        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return true; } }

        public override long Length
        {
            get
            {
                System.Runtime.InteropServices.ComTypes.STATSTG stats;
                this.istream.Stat(out stats, 1 /*STATFLAG_NONAME*/);
                return stats.cbSize;
            }
        }

        public unsafe override long Position
        {
            get
            {
                ulong newPosition;
                IntPtr newPositionPointer = new IntPtr(&newPosition);
                this.istream.Seek(0 /*offsetFromOrigin*/, 1 /*STREAM_SEEK_CUR*/, newPositionPointer);
                return (long)newPosition;
            }
            set
            {
                this.istream.Seek(value, 0 /*STREAM_SEEK_SET*/, IntPtr.Zero);
            }
        }

        public override void Flush()
        {
            this.istream.Commit(0 /*STGC_DEFAULT*/);
        }

        public unsafe override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset");
            }

            if ((buffer.Length - offset) < count)
            {
                throw new ArgumentException("offset + count > buffer.Length");
            }

            ulong bytesRead;
            IntPtr bytesReadPointer = new IntPtr(&bytesRead);
            int totalBytesRead = 0;

            if (offset == 0)
            {
                this.istream.Read(buffer, count, bytesReadPointer);
                totalBytesRead = (int)bytesRead;
            }
            else
            {
                int bytesRemaining = count;
                while (bytesRemaining > 0)
                {
                    int bytesToRead = Math.Min(bytesRemaining, this.tempBuffer.Length);
                    this.istream.Read(this.tempBuffer, bytesToRead, bytesReadPointer);
                    Buffer.BlockCopy(this.tempBuffer, 0, buffer, offset, (int)bytesRead);

                    bytesRemaining -= (int)bytesRead;
                    offset += (int)bytesRead;
                    totalBytesRead += (int)bytesRead;
                    if (bytesRead == 0)
                    {
                        bytesRemaining = 0;
                    }
                }
            }

            return totalBytesRead;
        }

        public unsafe override long Seek(long offset, SeekOrigin origin)
        {
            ulong newPosition;
            IntPtr newPositionPointer = new IntPtr(&newPosition);
            this.istream.Seek(offset, (int)origin, newPositionPointer);
            return (long)newPosition;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value");
            }

            this.istream.SetSize(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset");
            }

            if ((buffer.Length - offset) < count)
            {
                throw new ArgumentException("offset + count > buffer.Length");
            }

            if (offset == 0)
            {
                this.istream.Write(buffer, count, IntPtr.Zero);
            }
            else
            {
                // Note: if a custom offset is specified, we allocate a temp buffer for this write.
                // it'd be nicer to pass the original buffer in, but we can't increment its pointer
                // without using unsafe code.
                byte[] tempBuffer = new byte[count];
                Buffer.BlockCopy(buffer, offset, tempBuffer, 0, count);
                this.istream.Write(tempBuffer, count, IntPtr.Zero);
            }
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    GC.SuppressFinalize(this);
                }

                Marshal.ReleaseComObject(this.istream);
            }
            catch
            {
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }

    /// <summary>
    /// Wrapper over IStorage to help with cleanup
    /// </summary>
    public class OleStorage : IDisposable
    {
        public IStorage Storage { get; private set; }

        public OleStorage(IStorage storage)
        {
            this.Storage = storage;
        }

        public void  Dispose()
        {
            if (this.Storage != null)
            {
                Marshal.ReleaseComObject(this.Storage);
                this.Storage = null;
            }
        }
    }

    /// <summary>
    /// P/Invoke for OLE storages
    /// </summary>
    public static class OleWrap
    {
        [Flags]
        public enum STGM : uint
        {
            DIRECT = 0x00000000,
            TRANSACTED = 0x00010000,
            SIMPLE = 0x08000000,
            READ = 0x00000000,
            WRITE = 0x00000001,
            READWRITE = 0x00000002,
            SHARE_DENY_NONE = 0x00000040,
            SHARE_DENY_READ = 0x00000030,
            SHARE_DENY_WRITE = 0x00000020,
            SHARE_EXCLUSIVE = 0x00000010,
            PRIORITY = 0x00040000,
            DELETEONRELEASE = 0x04000000,
            NOSCRATCH = 0x00100000,
            CREATE = 0x00001000,
            CONVERT = 0x00020000,
            FAILIFTHERE = 0x00000000,
            NOSNAPSHOT = 0x00200000,
            DIRECT_SWMR = 0x00400000,

            ReadOnly = STGM.DIRECT | STGM.READ | STGM.SHARE_EXCLUSIVE,
            ReadWrite = STGM.DIRECT | STGM.READWRITE | STGM.SHARE_EXCLUSIVE,
            Create = STGM.CREATE | STGM.ReadWrite,
        }

        public enum STATFLAG : uint
        {
            STATFLAG_DEFAULT = 0,
            STATFLAG_NONAME = 1,
            STATFLAG_NOOPEN = 2
        }

        public enum STGFMT : uint
        {
            STGFMT_STORAGE = 0,
            STGFMT_FILE = 3,
            STGFMT_ANY = 4,
            STGFMT_DOCFILE = 5
        }
        
		[DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
		private static extern uint StgOpenStorage(string wzName, IntPtr pstgPriority, STGM grfMode,  IntPtr snb, uint reserved, out IStorage pstorage);

		[DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgCreateDocfile(string name, STGM grfMode, IntPtr reserved, out IStorage storage);

        /// <summary>
        /// Open an existing storage for read
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public static OleStorage OpenReadStorage(string file)
        {
            IStorage storage;
            StgOpenStorage(file, IntPtr.Zero, STGM.ReadOnly, IntPtr.Zero, 0, out storage);
            if (storage == null)
                throw new InvalidOperationException("Failed to open the storage");
            return new OleStorage(storage);
        }

        /// <summary>
        /// Create a new storage
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public static OleStorage CreateStorage(string file)
        {
            IStorage storage = null;
            StgCreateDocfile(file, STGM.Create, IntPtr.Zero, out storage);
            if (storage == null)
                throw new InvalidOperationException("Failed to create the storage");
            return new OleStorage(storage);
        }

        /// <summary>
        /// Open an existing stream for read
        /// </summary>
        /// <param name="storage"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Stream OpenReadStream(this IStorage storage, string name)
        {
            IStream istream;
            storage.OpenStream(name, IntPtr.Zero, (uint)(STGM.DIRECT | STGM.READ | STGM.SHARE_EXCLUSIVE), 0, out istream);
            if (istream == null)
                throw new InvalidOperationException("Failed to open the stream");
            try
            {
                return new StreamOnIStream(istream);
            }
            catch
            {
                Marshal.ReleaseComObject(istream);
                throw;
            }
        }

        /// <summary>
        /// Open an existing stream for read/write
        /// </summary>
        /// <param name="storage"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Stream OpenWriteStream(this IStorage storage, string name)
        {
            IStream istream;
            storage.OpenStream(name, IntPtr.Zero, (uint)(STGM.DIRECT | STGM.READWRITE | STGM.SHARE_EXCLUSIVE), 0, out istream);
            if (istream == null)
                throw new InvalidOperationException("Failed to open the stream");
            try
            {
                return new StreamOnIStream(istream);
            }
            catch
            {
                Marshal.ReleaseComObject(istream);
                throw;
            }
        }

        /// <summary>
        /// Create a new stream
        /// </summary>
        /// <param name="storage"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Stream CreateWriteStream(this IStorage storage, string name)
        {
            IStream istream;
            storage.CreateStream(name, (uint)(STGM.CREATE | STGM.DIRECT | STGM.READWRITE | STGM.SHARE_EXCLUSIVE), 0, 0, out istream);
            if (istream == null)
                throw new InvalidOperationException("Failed to create the stream");
            try
            {
                return new StreamOnIStream(istream);
            }
            catch
            {
                Marshal.ReleaseComObject(istream);
                throw;
            }
        }

        /// <summary>
        /// Copy a file into a new stream
        /// </summary>
        /// <param name="storage"></param>
        /// <param name="streamName"></param>
        /// <param name="file"></param>
        public static void CopyFromFile(this IStorage storage, string streamName, string file)
        {
            var outStream = storage.CreateWriteStream(streamName);
            using (outStream)
            {
                outStream.CopyFromFile(file);
            }
        }

        /// <summary>
        /// Copy a stream into a new file
        /// </summary>
        /// <param name="storage"></param>
        /// <param name="streamName"></param>
        /// <param name="file"></param>
        public static void CopyToFile(this IStorage storage, string streamName, string file)
        {
            var inStream = storage.OpenReadStream(streamName);
            using (inStream)
            {
                inStream.CopyToFile(file);
            }
        }
    }
}
