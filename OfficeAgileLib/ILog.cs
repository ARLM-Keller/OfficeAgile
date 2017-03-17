using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.Office.Crypto.Agile
{
    public interface ILog
    {
        void WriteLine(int indent, string value);
        void WriteBytes(int indent, string name, byte[] bytes);
    }

    /// <summary>
    /// Simple logging mechanism, not thread-safe
    /// </summary>
    public static class Log
    {
        private static Stack<string> scopes = new Stack<string>();

        public static ILog Instance = new ConsoleLog();

        public static void WriteLine(string name, params object[] args)
        {
            Instance.WriteLine(IndentLevel(), String.Format(name, args));
        }

        public static void WriteBytes(string value, byte[] bytes)
        {
            Instance.WriteBytes(IndentLevel(), value, bytes);
        }

        public static String PeekScope()
        {
            return scopes.FirstOrDefault();
        }

        public static void PopScope()
        {
            scopes.Pop();
        }

        public static void PushScope(string value)
        {
            Instance.WriteLine(IndentLevel(), String.Format("({0})", value));
            scopes.Push(value);
        }

        public static int IndentLevel()
        {
            return scopes.Count;
        }
    }

    /// <summary>
    /// Console implementation of ILog
    /// </summary>
    public class ConsoleLog : ILog
    {
        public ConsoleLog()
        {
        }

        public void WriteIndent(int indent)
        {
            // TODO: probably a nicer way to do this
            for (int i = 0; i < indent; i++)
                Console.Write("  ");
        }

        public void WriteLine(int indent, string value)
        {
            WriteIndent(indent);
            Console.WriteLine(value);
        }

        public void WriteBytes(int indent, string name, byte[] bytes)
        {
            WriteIndent(indent);
            Console.Write(name);
            Console.WriteLine("[{0}]=", bytes.Length);

            WriteIndent(indent);
            Console.WriteLine("{");

            int i = 0;
            while (i < bytes.Length)
            {
                if ((i % 16) == 0)
                {
                    WriteIndent(indent + 1);
                }

                Console.Write("0x{0:X2}, ", bytes[i]);

                i++;
                if ((i % 16) == 0)
                {
                    Console.WriteLine();
                }
            }
            Console.WriteLine();

            WriteIndent(indent);
            Console.WriteLine("};");
        }
    }
}
