using System;
using System.Collections;
using System.IO;
using System.Text;

namespace AESHash.AvalanceEffect
{
    public class AvalancheEffect
    {
        public void SaveCsvResult(string path)
        {
            var csv = new StringBuilder();
            var count = 100;
            var aesHash = new AESHASH();
            var x = new byte[count][];
            var y = new byte[count][];
            for (int i = 0; i < x.Length; i++)
            {
                var message = Randomizer.GetRandomString();
                var messageBytes = Encoding.ASCII.GetBytes(message);
                x[i] = messageBytes;
                y[i] = GetModifiedBy1BitBytes(x[i]);

                x[i] = aesHash.GetHash(x[i]);
                y[i] = aesHash.GetHash(y[i]);

                csv.Append($"{i + 1};{GetHammingDistance(x[i], y[i])}{Environment.NewLine}");

                Console.WriteLine(BitConverter.ToString(x[i]));
                Console.WriteLine(BitConverter.ToString(y[i]));
                Console.WriteLine(GetHammingDistance(x[i], y[i]));
            }
            File.WriteAllText(path, csv.ToString());
        }

        private int GetHammingDistance(byte[] x, byte[] y)
        {
            var distance = 0;
            var xbits = new BitArray(x);
            var ybits = new BitArray(y);
            for (int i = 0; i < xbits.Length; i++)
            {
                distance += xbits[i] == ybits[i] ? 0 : 1;
            }
            return distance;
        }

        private byte[] GetModifiedBy1BitBytes(byte[] x)
        {
            var y = new byte[x.Length];
            Array.Copy(x, y, y.Length);
            var bytePosition = Randomizer.GetRandomInt(0, x.Length);
            var bitPosition = Randomizer.GetRandomInt(0, 8);
            var changingByte = y[bytePosition];
            var mask = (byte)(1 << bitPosition);
            var isSet = (changingByte & mask) != 0;
            if (isSet)
            {
                changingByte &= (byte)~mask;
            }
            else
            {
                changingByte |= mask;
            }
            y[bytePosition] = changingByte;
            return y;
        }
    }
}
