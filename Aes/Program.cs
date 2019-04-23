using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aes
{
    public static class GFMultHelper
    {
        public static byte MultBy1(byte input)
        {
            return input;
        }

        public static byte MultBy2(byte input)
        {
            if (input >= 0x80)
            {
                return (byte)(input << 1 ^ 0x1B);
            }

            return (byte)(input * 2);
        }

        public static byte MultBy3(byte input)
        {
            return (byte)(input ^ MultBy2(input));
        }

        public static byte MultByE(byte input)
        {
            return (byte)(MultBy8(input) ^ MultBy4(input) ^ MultBy2(input));
        }

        public static byte MultByB(byte input)
        {
            return (byte)(MultBy8(input) ^ MultBy2(input) ^ input);
        }

        public static byte MultByD(byte input)
        {
            return (byte)(MultBy8(input) ^ MultBy4(input) ^ input);
        }

        public static byte MultBy4(byte input)
        {
            return MultBy2(MultBy2(input));
        }

        public static byte MultBy8(byte input)
        {
            return MultBy2(MultBy4(input));
        }

        public static byte MultBy9(byte input)
        {
            return (byte)(MultBy8(input) ^ input);
        }
    }

    public class AES
    {
        byte[,] Sbox = new byte[,] {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };

        byte[,] InvSbox = new byte[,]{
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        byte[,] Rcon = new byte[,]{
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00}
        };

        byte[,] mixColumnsMult;

        byte[,] invMixColumnsMult;

        byte[] mixColumns = { 1, 2, 0, 0 };

        byte[] invMixColumns = { 3, 1, 2, 0 };

        byte Nr = 10;

        // число столбцов (32-битных слов), составляющих State. Для AES Nb = 4
        int Nb = 4;

        // число 32-битных слов, составляющих шифроключ. Для AES Nk = 4, 6, или 8
        int Nk = 4;

        // число строк в State
        int R = 4;

        byte[,] State;

        byte[,] RoundKeys;

        public AES()
        {
            RoundKeys = new byte[R, (Nr + 1) * Nb];
            mixColumnsMult = new byte[256, 3];
            invMixColumnsMult = new byte[256, 4];

            for (int j = 0; j < 256; j++)
            {
                var i = (byte)j;
                mixColumnsMult[i, 0] = GFMultHelper.MultBy1(i);
                mixColumnsMult[i, 1] = GFMultHelper.MultBy2(i);
                mixColumnsMult[i, 2] = GFMultHelper.MultBy3(i);

                invMixColumnsMult[i, 0] = GFMultHelper.MultBy9(i);
                invMixColumnsMult[i, 1] = GFMultHelper.MultByB(i);
                invMixColumnsMult[i, 2] = GFMultHelper.MultByD(i);
                invMixColumnsMult[i, 3] = GFMultHelper.MultByE(i);
            }
        }

        public byte[] Encrypt(byte[] input, byte[] cipherKey)
        {
            CopyInput(input);
            ComputeRoundKeys(cipherKey);

            AddRoundKey(0);

            for (int i = 1; i < Nr; i++)
            {
                SubBytes();
                ShiftRows();
                MixColumns();
                AddRoundKey(i);
            }

            SubBytes();
            ShiftRows();
            AddRoundKey(Nr);

            return GetFlattenedState();
        }

        public byte[] Decrypt(byte[] input, byte[] cipherKey)
        {
            CopyInput(input);
            ComputeRoundKeys(cipherKey);

            AddRoundKey(Nr);

            for (int i = Nr - 1; i >= 1; i--)
            {
                InvShiftRows();
                InvSubBytes();
                AddRoundKey(i);
                InvMixColumns();
            }

            InvShiftRows();
            InvSubBytes();
            AddRoundKey(0);

            return GetFlattenedState();
        }

        private void CopyInput(byte[] input)
        {
            State = new byte[R, Nb];

            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    State[i, j] = input[i + 4 * j];
                }
            }
        }

        private void ComputeRoundKeys(byte[] cipherKey)
        {
            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    RoundKeys[i, j] = cipherKey[i + Nb * j];
                }
            }

            for (int i = 1; i <= Nr; i++)
            {
                var firstBlockColumn = GetFirstRoundKeyBlockColumn(i - 1);
                var firstBlockColumnIndex = i * Nb;
                for (int j = 0; j < R; j++)
                {
                    RoundKeys[j, firstBlockColumnIndex] = firstBlockColumn[j];
                }

                for (int j = 1; j < Nb; j++)
                {
                    for (int k = 0; k < R; k++)
                    {
                        var currColumn = firstBlockColumnIndex + j;
                        RoundKeys[k, currColumn] = (byte)(RoundKeys[k, currColumn - Nb] ^ RoundKeys[k, currColumn - 1]);
                    }
                }
            }
        }

        private byte[] GetFirstRoundKeyBlockColumn(int round)
        {
            var columnIndex = (round + 1) * Nb;
            var column = new byte[R];
            for (int i = 0; i < R; i++)
            {
                column[i] = RoundKeys[(i + 1) % R, columnIndex - 1];
                var i1 = column[i] >> 4;
                var i2 = column[i] & 0xF;
                column[i] = Sbox[i1, i2];
                column[i] ^= RoundKeys[i, columnIndex - Nb];
                column[i] ^= Rcon[round, i];
            }
            return column;
        }

        private void SubBytes()
        {
            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    var i1 = State[i, j] >> 4;
                    var i2 = State[i, j] & 0xF;
                    State[i, j] = Sbox[i1, i2];
                }
            }
        }

        private void InvSubBytes()
        {
            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    var i1 = State[i, j] >> 4;
                    var i2 = State[i, j] & 0xF;
                    State[i, j] = InvSbox[i1, i2];
                }
            }
        }

        private void ShiftRows()
        {
            for (int i = 1; i < R; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    ShiftRow(i);
                }
            }
        }

        private void InvShiftRows()
        {
            for (int i = 1; i < R; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    InvShiftRow(i);
                }
            }
        }

        private void ShiftRow(int rowIndex)
        {
            var first = State[rowIndex, 0];
            for (int i = 0; i < Nb - 1; i++)
            {
                State[rowIndex, i] = State[rowIndex, i + 1];
            }
            State[rowIndex, Nb - 1] = first;
        }

        private void InvShiftRow(int rowIndex)
        {
            var last = State[rowIndex, Nb - 1];
            for (int i = Nb - 1; i > 0; i--)
            {
                State[rowIndex, i] = State[rowIndex, i - 1];
            }
            State[rowIndex, 0] = last;
        }

        private void InvMixColumns()
        {
            MixColumns(true);
        }

        private void MixColumns(bool isInverse = false)
        {
            for (int i = 0; i < Nb; i++)
            {
                var newColumn = GetMixedColumn(i, isInverse);
                for (int j = 0; j < R; j++)
                {
                    State[j, i] = newColumn[j];
                }
            }
        }

        private byte[] GetMixedColumn(int columnIndex, bool isInverse = false)
        {
            var mixedColumn = new byte[R];
            for (int i = 0; i < R; i++)
            {
                mixedColumn[i] = GetMixedElement(columnIndex, i, isInverse);
            }
            return mixedColumn;
        }

        private byte GetMixedElement(int columnIndex, int offset, bool isInverse = false)
        {
            var mixCol = isInverse ? invMixColumns : mixColumns;
            var mixColMult = isInverse ? invMixColumnsMult : mixColumnsMult;
            var element = mixColMult[State[0, columnIndex], mixCol[(-offset + R) % R]];
            for (int i = 1; i < R; i++)
            {
                var actionIndex = (i - offset + R) % R;
                element ^= mixColMult[State[i, columnIndex], mixCol[actionIndex]];
            }
            return element;
        }

        private void AddRoundKey(int round)
        {
            for (int i = 0; i < R; i++)
            {
                for(int j = 0; j < Nb; j++)
                {
                    State[i, j] ^= RoundKeys[i, round * Nb + j];
                }
            }
        }

        private byte[] GetFlattenedState()
        {
            var output = new byte[State.Length];
            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    output[i + 4 * j] = State[i, j];
                }
            }
            return output;
        }

        private void PrintState()
        {
            for(int i = 0; i < R; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    Console.Write(Convert.ToString(State[i, j], 16) + " ");
                }
                Console.WriteLine();
            }
        }

        private void PrintRoundKeys()
        {
            for (int i = 0; i < R; i++)
            {
                for (int j = 0; j < RoundKeys.Length / R; j++)
                {
                    Console.Write(Convert.ToString(RoundKeys[i, j], 16) + " ");
                }
                Console.WriteLine();
            }
        }
    }

    public static class ArrayExtensions
    {
        public static T[][] Split<T>(this T[] array, int blockSize)
        {
            var blocksCount = array.Length / blockSize;
            var result = new T[blocksCount][];
            for (int i = 0; i < blocksCount; i++)
            {
                result[i] = new T[blockSize];
                var blockBeginIndex = i * blockSize;
                for (int j = 0; j < blockSize; j++)
                {
                    result[i][j] = array[blockBeginIndex + j];
                }
            }
            return result;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            //var filePath = @"D:\AESTEST\funniest_home_videos_part_10.mp4";
            //var fileEncryptedPath = @"D:\AESTEST\funniest_home_videos_part_10(Encrypted).mp4";
            //var fileDecryptedPath = @"D:\AESTEST\funniest_home_videos_part_10(Decrypted).mp4";

            var filePath = @"D:\AESTEST\New Text Document.txt";
            var fileEncryptedPath = @"D:\AESTEST\New Text Document(Encrypted).txt";
            var fileDecryptedPath = @"D:\AESTEST\New Text Document(Decrypted).txt";

            Console.WriteLine("Ecnryption started");
            var T1 = new Stopwatch();
            T1.Start();
            EncryptFile(filePath, fileEncryptedPath, "123456");
            T1.Stop();
            Console.WriteLine("Elapsed ecnrypted: " + T1.ElapsedMilliseconds / 1000.0);

            Console.WriteLine("Decryption started");
            var T2 = new Stopwatch();
            T2.Start();
            DecryptFile(fileEncryptedPath, fileDecryptedPath, "123456");
            T2.Stop();
            Console.WriteLine("Elapsed decrypted: " + T1.ElapsedMilliseconds / 1000.0);
        }

        private static void EncryptFile(string filePath, string fileOutputPath, string password)
        {
            var aes = new AES();
            var cipherKey = GetMD5Hash(password);
            var bytes = File.ReadAllBytes(filePath);
            var blocks = bytes.Split(16);
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = aes.Decrypt(blocks[i], cipherKey);
            }
            var decrypted = blocks.SelectMany(x => x).ToArray();
            File.WriteAllBytes(fileOutputPath, decrypted);
        }

        private static void DecryptFile(string filePath, string fileOutputPath, string password)
        {
            var aes = new AES();
            var cipherKey = GetMD5Hash(password);
            var encrypted = File.ReadAllBytes(filePath);
            var blocks = encrypted.Split(16);
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = aes.Decrypt(blocks[i], cipherKey);
            }
            var decrypted = blocks.SelectMany(x => x).ToArray();
            File.WriteAllBytes(fileOutputPath, decrypted);
        }

        public static byte[] GetMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                return md5.ComputeHash(inputBytes);
            }
        }

        private static void CheckEncrypted(byte[] encrypted)
        {
            var ans = GetBytesString(encrypted);
            Console.WriteLine(ans);
            Console.WriteLine(ans == "39 25 84 1d 2 dc 9 fb dc 11 85 97 19 6a b 32 ");
        }

        private static string GetBytesString(byte[] bytes)
        {
            string ans = "";
            foreach (var b in bytes)
            {
                ans += Convert.ToString(b, 16) + " ";
            }
            return ans;
        }
    }
}
