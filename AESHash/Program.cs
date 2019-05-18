using Aes;
using AESHash.AvalanceEffect;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AESHash
{
    public class AESHASH
    {
        // 128 bit
        private const int Nb = 16;

        private const int N = 16;

        private readonly AES aes;

        public AESHASH()
        {
            aes = new AES();
        }

        public virtual byte[] GetHash(byte[] input)
        {
            var X = GetInputBlocks(input);
            AddSizeBlock(ref X, input.Length);
            var Y = GetInitialHash();
            return GetHash(X, Y);
        }

        public virtual ulong GetLongHash(byte[] input)
        {
            throw new NotSupportedException();
        }

        private byte[] GetHash(byte[][] X, byte[] Y)
        {
            for (int i = 0; i < X.Length; i++)
            {
                Y = GetSigmaResult(X[i], Y);
            }
            return Y;
        }

        private byte[][] GetInputBlocks(byte[] input)
        {
            var m = Nb - input.Length % Nb;
            Array.Resize(ref input, input.Length + m);
            return input.Split(Nb);
        }

        private byte[] GetInitialHash()
        {
            return new byte[N] { 83, 251, 3, 231, 5, 6, 70, 8, 9, 10, 91, 165, 93, 14, 75, 184 };
        }

        private void AddSizeBlock(ref byte[][] X, int size)
        {
            Array.Resize(ref X, X.Length + 1);
            var lastBlockIndex = X.Length - 1;
            X[lastBlockIndex] = new byte[Nb];
            X[lastBlockIndex][0] = (byte)(size >> 24);
            X[lastBlockIndex][1] = (byte)(size >> 16);
            X[lastBlockIndex][2] = (byte)(size >> 8);
            X[lastBlockIndex][3] = (byte)(size);
        }

        private byte[] GetSigmaResult(byte[] X, byte[] Y)
        {
            var encrypted = aes.Encrypt(X, Y);
            return Xor(encrypted, X);
        }

        protected byte[] Xor(byte[] bytes1, byte[] bytes2)
        {
            var ret = new byte[bytes1.Length];
            for (int i = 0; i < ret.Length; i++)
            {
                ret[i] = (byte)(bytes1[i] ^ bytes2[i]);
            }
            return ret;
        }
    }

    public class AESHASH32 : AESHASH
    {
        public override byte[] GetHash(byte[] input)
        {
            var hash = base.GetHash(input);
            var ret = new byte[4]
            {
                hash[0], hash[1], hash[2], hash[3]
            };
            return ret;
        }

        public override ulong GetLongHash(byte[] input)
        {
            var hash = base.GetHash(input);
            return (ulong)BitConverter.ToUInt32(hash, 0);
        }
    }

    public class AESHASH48 : AESHASH
    {
        public override byte[] GetHash(byte[] input)
        {
            var hash = base.GetHash(input);
            var ret = new byte[6]
            {
                hash[0], hash[1], hash[2],
                hash[3], hash[4], hash[5]
            };
            return ret;
        }

        public override ulong GetLongHash(byte[] input)
        {
            var hash = base.GetHash(input);
            return (ulong)(BitConverter.ToUInt32(hash, 0) << 16 | hash[4] << 8 | hash[5]);
        }
    }

    public class AESHASH24 : AESHASH
    {
        public override byte[] GetHash(byte[] input)
        {
            var hash = base.GetHash(input);
            var ret = new byte[3]
            {
                hash[0], hash[1], hash[2]
            };
            return ret;
        }

        public override ulong GetLongHash(byte[] input)
        {
            var hash = base.GetHash(input);
            return (ulong)BitConverter.ToUInt16(hash, 0) << 8 | hash[2];
        }
    }

    public class AESHASH64 : AESHASH
    {
        public override byte[] GetHash(byte[] input)
        {
            var hash = base.GetHash(input);
            var ret = new byte[8]
            {
                hash[0], hash[1], hash[2], hash[3],
                hash[4], hash[5], hash[6], hash[7]
            };
            return ret;
        }

        public override ulong GetLongHash(byte[] input)
        {
            var hash = base.GetHash(input);
            return BitConverter.ToUInt64(hash, 0);
        }
    }

    public static class EqualityHelper
    {
        public static bool AreByteArrayEqual(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }
    }

    public static class Randomizer
    {
        private static readonly Random rand;

        private static readonly int asciiFirstStart = 32;

        private static readonly int asciiFirstEnd = 126;

        private static readonly int asciiSecondStart = 161;

        private static readonly int asciiSecondEnd = 256;

        static Randomizer()
        {
            rand = new Random();
        }

        public static int GetRandomInt(int minValue, int maxValue)
        {
            return rand.Next(minValue, maxValue);
        }

        public static bool GetRandomBool()
        {
            return rand.Next(0, 2) == 1;
        }

        public static string GetRandomAlphabeticString()
        {
            var tripleString = Path.GetRandomFileName() + Path.GetRandomFileName() + Path.GetRandomFileName();
            return tripleString.Replace(".", "");
        }

        public static string GetRandomString()
        {
            var n = rand.Next(159, 381);
            return GetRandomNString(n);
        }

        public static string GetRandomNString(int n)
        {
            var str = new char[n];
            for (int i = 0; i < str.Length; i++)
            {
                if (rand.Next(0, 2) == 1)
                {
                    str[i] = (char)rand.Next(asciiFirstStart, asciiFirstEnd + 1);
                }
                else
                {
                    str[i] = (char)rand.Next(asciiSecondStart, asciiSecondEnd + 1);
                }
            }
            return new string(str);
        }

        public static byte[] GetRandomBytes()
        {
            var ret = new byte[rand.Next(7, 95)];
            rand.NextBytes(ret);
            return ret;
        }
    }

    public static class PrintHelper
    {
        public static void PrintFileHash(string path)
        {
            var aesHash = new AESHASH();
            var content = File.ReadAllBytes(path);
            var hash = aesHash.GetHash(content);
            var stringHashHex = BitConverter.ToString(hash);

            Console.WriteLine(stringHashHex);
        }

        public static void PrintBytes(byte[] bytes)
        {
            var str = BitConverter.ToString(bytes);
            Console.WriteLine(str);
        }

        public static void PrintAesHash(AESHASH aesHash, string str)
        {
            var bytes = Encoding.ASCII.GetBytes(str);
            var hash = aesHash.GetHash(bytes);
            var longHash = aesHash.GetLongHash(bytes);

            Console.WriteLine("__________________________________________");
            Console.WriteLine("    String: " + str);
            Console.WriteLine("Hash bytes: " + BitConverter.ToString(hash));
            Console.WriteLine(" Long hash: " + longHash);
        }
    }

    public class HashCache
    {
        private readonly Dictionary<ulong, string> cache;

        private readonly int diskDropItemsCountThreshold = 1000000;

        private readonly string cacheFileName = "cache.txt";

        private readonly object syncObject;

        public HashCache()
        {
            File.Delete(cacheFileName);
            syncObject = new object();
            cache = new Dictionary<ulong, string>();
        }

        public void Add(ulong hash, string str)
        {
            lock (syncObject)
            {
                if (cache.ContainsKey(hash) || cache.Count > diskDropItemsCountThreshold)
                {
                    PerformDiskDrop();
                }

                cache.Add(hash, str);
            }
        }

        public string[] Get(ulong hash)
        {
            PerformDiskDrop();
            var result = new string[2];
            var hashS = hash.ToString();
            var i = 0;
            using (var fileStream = File.OpenRead(cacheFileName))
            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true))
            {
                String line;
                while ((line = streamReader.ReadLine()) != null)
                {
                    var pair = line.Split('\0');
                    if (pair[0] == hashS)
                    {
                        result[i] = pair[1];
                        i++;
                        if (i == 2)
                        {
                            return result;
                        }
                    }
                }
            }
            return result;
        }

        private void PerformDiskDrop()
        {
            var sb = new StringBuilder();
            foreach (var key in cache.Keys)
            {
                var str = cache[key];
                sb.Append($"{key}{'\0'}{str}{Environment.NewLine}");
            }
            File.AppendAllText(cacheFileName, sb.ToString());
            cache.Clear();
        }
    }

    public class CollisionFinder
    {
        private readonly HashCache hashCache;

        public CollisionFinder()
        {
            hashCache = new HashCache();
        }

        public string[] GetCollision(AESHASH aesHash)
        {
            var set = new HashSet<ulong>();

            long i = 0;
            while (true)
            {
                var randomString = Randomizer.GetRandomString();
                var randomBytes = Encoding.ASCII.GetBytes(randomString);
                var hash = aesHash.GetLongHash(randomBytes);
                hashCache.Add(hash, randomString);

                if (set.Contains(hash))
                {
                    Console.WriteLine($"{DateTime.Now} {i}");
                    return hashCache.Get(hash);
                }
                else
                {
                    set.Add(hash);
                }

                if (i % 1000000 == 0)
                {
                    Console.WriteLine($"{DateTime.Now} {i}");
                }
                i++;
            }
        }

        public string GetCollision(AESHASH aesHash, string collisionString)
        {
            var collisionBytes = Encoding.ASCII.GetBytes(collisionString);
            var collisionHash = aesHash.GetLongHash(collisionBytes);

            long i = 0;
            while (true)
            {
                var randomString = Randomizer.GetRandomString();
                var randomBytes = Encoding.ASCII.GetBytes(randomString);
                var randomHash = aesHash.GetLongHash(randomBytes);

                if (randomHash == collisionHash)
                {
                    Console.WriteLine($"{DateTime.Now} {i}");
                    return randomString;
                }

                if (i % 1000000 == 0)
                {
                    Console.WriteLine($"{DateTime.Now} {i}");
                }
                i++;
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.GetEncoding("cp850");

            //FindCollision();
            SaveAvalancheEffect();
            Print24BitCollision();
            Print64BitCollision();

            //PrintHelper.PrintFileHash(@"C:\Users\Rodion\Downloads\all-projects.txt");
        }

        private static void SaveAvalancheEffect()
        {
            var avalancheEffect = new AvalancheEffect();
            avalancheEffect.SaveCsvResult("avalancheEffect.csv");
        }

        private static void FindCollision()
        {
            var aesHash = new AESHASH64();
            var collision = new CollisionFinder().GetCollision(aesHash);
            PrintHelper.PrintAesHash(aesHash, collision[0]);
            PrintHelper.PrintAesHash(aesHash, collision[1]);
        }

        private static void Print64BitCollision()
        {
            var aesHash = new AESHASH64();
            Console.WriteLine("##################################################################### AES Hash collision 64 bit:");
            PrintHelper.PrintAesHash(aesHash, "³³ïî»¿ÇÈ©Ú¥ê²¨ºáçùû¼ö±Ì");
            PrintHelper.PrintAesHash(aesHash, "ûÃþôÔ¶ÐÞëåêØúíéÆ®ç­£êâ¯");
        }

        private static void Print24BitCollision()
        {
            var aesHash = new AESHASH24();
            Console.WriteLine("##################################################################### AES Hash collision 24 bit:");
            PrintHelper.PrintAesHash(aesHash, "Rodion found this collision for 24 bit hash!!! Keep up a good work :)");
            PrintHelper.PrintAesHash(aesHash, "Kwª«C?*½/ô");
        }
    }
}
