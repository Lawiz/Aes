using Aes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AESHash
{
    public class AESHASH
    {
        private readonly AES aes;

        private readonly int Nb;

        private readonly int N;

        public AESHASH(int blockSize)//, int outputSize)
        {
            aes = new AES();
            Nb = blockSize;
            N = blockSize;
            //N = outputSize;
        }

        public byte[] GetHash(byte[] input)
        {
            int m = Nb - input.Length % Nb;
            var blocks = input.Split(Nb);
            Array.Resize(ref blocks[blocks.Length - 1], Nb);
            SetInputLength(ref blocks, input);

            var Y = GetInitialState(N);
        }

        public string GetHash(string input)
        {

        }

        private byte[] GetInitialState(int size)
        {
            var initialState = new byte[size];
            for (int i = 0; i < size; i++)
            {
                initialState[i] = (byte)(i % 256);
            }
            return initialState;
        }

        private void SetInputLength(ref byte[][] blocks, byte[] input)
        {
            Array.Resize(ref blocks, blocks.Length + 1);
            var inputLength = input.Length;

            blocks[blocks.Length - 1][0] = (byte)(inputLength >> 24);
            blocks[blocks.Length - 1][1] = (byte)(inputLength >> 16);
            blocks[blocks.Length - 1][2] = (byte)(inputLength >> 8);
            blocks[blocks.Length - 1][3] = (byte)(inputLength >> 0);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
        }
    }
}
