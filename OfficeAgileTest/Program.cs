using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;

namespace Microsoft.Office.Crypto.Agile
{
    class Program
    {
        /// <summary>
        /// Copy the OLE Storage into temp files
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="infoFile"></param>
        /// <param name="packageFile"></param>
        private static void FileToStreams(string inputFile, string infoFile, string packageFile)
        {
            var oleStorage = OleWrap.OpenReadStorage(inputFile);
            using (oleStorage)
            {
                oleStorage.Storage.CopyToFile("EncryptionInfo", infoFile);
                oleStorage.Storage.CopyToFile("EncryptedPackage", packageFile);
            }
        }

        /// <summary>
        /// Copy the temp files into a new OLE storage
        /// </summary>
        /// <param name="infoFile"></param>
        /// <param name="packageFile"></param>
        /// <param name="outputFile"></param>
        private static void StreamsToFile(string infoFile, string packageFile, string outputFile)
        {
            var oleStorage = OleWrap.CreateStorage(outputFile);
            using (oleStorage)
            {
                oleStorage.Storage.CopyFromFile("EncryptionInfo", infoFile);
                oleStorage.Storage.CopyFromFile("EncryptedPackage", packageFile);
            }
        }

        /// <summary>
        /// Load the encryption session from a given file
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        private static EncryptionSession LoadFromFile(string file)
        {
            var fileStream = new FileInfo(file).OpenRead();
            using (fileStream)
            {
                return EncryptionSession.LoadFromStream(fileStream);
            }
        }

        /// <summary>
        /// Decrypt the package into a file
        /// </summary>
        /// <param name="session"></param>
        /// <param name="encryptedPackageFile"></param>
        /// <param name="decryptedPackageFile"></param>
        private static void DecryptPackage(EncryptionSession session, string encryptedPackageFile, string decryptedPackageFile)
        {
            var encryptedPackageStream = File.OpenRead(encryptedPackageFile);
            using (encryptedPackageStream)
            {
                bool isValid = session.DoIntegrityCheck(encryptedPackageStream);
                Console.WriteLine("Integrity check: " + isValid);

                var decryptedPackageStreamRead = session.GetEncryptedStream(encryptedPackageStream);
                using (decryptedPackageStreamRead)
                {
                    decryptedPackageStreamRead.CopyToFile(decryptedPackageFile);
                }
            }
        }

        /// <summary>
        /// Encrypt the package from a file
        /// </summary>
        /// <param name="session"></param>
        /// <param name="decryptedPackageFile"></param>
        /// <param name="encryptedPackageFile"></param>
        private static void EncryptPackage(EncryptionSession session, string decryptedPackageFile, string encryptedPackageFile)
        {
            var encryptedPackageStream = File.Open(encryptedPackageFile, FileMode.Create, FileAccess.ReadWrite);
            using (encryptedPackageStream)
            {
                var encryptedPackageStreamWrapper = session.GetEncryptedStream(encryptedPackageStream);
                using (encryptedPackageStreamWrapper)
                {
                    encryptedPackageStreamWrapper.CopyFromFile(decryptedPackageFile);
                }

                session.AddIntegrityCheck(encryptedPackageStream);
            }
        }

        /// <summary>
        /// Write the encryption session out to disk
        /// </summary>
        /// <param name="session"></param>
        /// <param name="file"></param>
        private static void WriteToXml(EncryptionSession session, string file)
        {
            var encryptionInfoStream = File.Open(file, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            using (encryptionInfoStream)
            {
                session.WriteToStream(encryptionInfoStream);
            }
        }

        /// <summary>
        /// Test code
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Log.WriteLine("Usage:\n{0} <encryptedFile> <password>", Path.GetFileName(Assembly.GetEntryAssembly().Location));
                return;
            }

            FileInfo encryptedFile = new FileInfo(args[0]);
            if (!encryptedFile.Exists)
            {
                Log.WriteLine("{0} doesn't exist", encryptedFile.FullName);
                return;
            }

            DirectoryInfo workingFolder = new DirectoryInfo(encryptedFile.FullName + "_Files");
            if (workingFolder.Exists)
            {
                try { workingFolder.Delete(true); }
                catch(Exception) { Log.WriteLine("Warning: failed to clear {0}exist", workingFolder.FullName); }
            }
            workingFolder.Create();

            string originalEncryptionInfoFile = Path.Combine(workingFolder.FullName, "originalEncryptionInfo.bin");
            string originalEncryptedPackageFile = Path.Combine(workingFolder.FullName, "originalEncryptedPackage.bin");
            string originalDecryptedPackageFile = Path.Combine(workingFolder.FullName, "originalDecryptedPackage.zip");
            string newEncryptedPackageFile = Path.Combine(workingFolder.FullName, "newEncryptedPackage.bin");
            string newEncryptionInfoFile = Path.Combine(workingFolder.FullName, "newEncryptionInfo.bin");
            string newEncryptedFile = Path.Combine(workingFolder.FullName, "newEncryptedDocument" + encryptedFile.Extension);

            FileToStreams(encryptedFile.FullName, originalEncryptionInfoFile, originalEncryptedPackageFile);

            var session = LoadFromFile(originalEncryptionInfoFile);
            session.UnlockWithPassword(args[1]);

            DecryptPackage(session, originalEncryptedPackageFile, originalDecryptedPackageFile);
            EncryptPackage(session, originalDecryptedPackageFile, newEncryptedPackageFile);

            WriteToXml(session, newEncryptionInfoFile);

            StreamsToFile(newEncryptionInfoFile, newEncryptedPackageFile, newEncryptedFile);

            Console.ReadLine();
        }
    }
}