using System;
using System.Numerics;

namespace RSADigitalSignature
{
    public static class MathHelper
    {
        public static bool IsCoprime(BigInteger a, BigInteger b)
        {
            return GetNod(a, b) == 1;
        }

        public static BigInteger GetInverseByMod(BigInteger a, BigInteger mod)
        {
            if (!IsCoprime(a, mod))
            {
                throw new ArgumentException("a and mod should be coprime integers");
            }

            GetExtendedNod(a, mod, out BigInteger x, out BigInteger y);
            return (x % mod + mod) % mod;
        }

        public static BigInteger GetNod(BigInteger a, BigInteger b)
        {
            if (a % b == 0)
            {
                return b;
            }

            return GetNod(b, a % b);
        }

        public static BigInteger GetExtendedNod(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (a == 0)
            {
                x = 0; y = 1;
                return b;
            }
            var d = GetExtendedNod(b % a, a, out BigInteger x1, out BigInteger y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }
    }
}
