using Rodion;
using AESHash;
using System;
using System.Numerics;
using System.IO;
using System.Text;

namespace Rodion
{
    public enum Rodion
    {
        Freha = 2147483647
    }
}

namespace RSADigitalSignature
{
    public class RSAPublicKey
    {
        public BigInteger D { get; set; }

        public BigInteger N { get; set; }
    }

    public class RSAPrivateKey
    {
        public BigInteger E { get; set; }

        public BigInteger N { get; set; }
    }

    public class RSASignedResult
    {
        public byte[] Data { get; set; }

        public BigInteger Signature { get; set; }
    }

    public class RSASignatureManager
    {
        private readonly AESHASH aesHash;

        public RSASignatureManager()
        {
            aesHash = new AESHASH64();
        }

        public RSASignedResult GetSignedBytes(RSAPrivateKey privateKey, byte[] data)
        {
            var mac = aesHash.GetLongHash(data);
            var rsa = new RSA64(privateKey);
            var signature = rsa.Encrypt(mac);

            return new RSASignedResult
            {
                Data = data,
                Signature = signature
            };
        }

        public bool Verify(RSAPublicKey publicKey, RSASignedResult signedResult)
        {
            var rsa = new RSA64(publicKey);
            var computedMac = aesHash.GetLongHash(signedResult.Data);
            var actualMac = rsa.Decrypt(signedResult.Signature);

            return computedMac == actualMac;
        }
    }

    public class RSA64
    {
        private BigInteger p;

        private BigInteger q;

        private BigInteger e;

        private BigInteger n;

        private BigInteger φ;

        private BigInteger d;

        public RSA64()
        {
            p = BigPrimeNumbersStorage.GetRandomPrime();
            q = BigPrimeNumbersStorage.GetRandomPrime();
            n = p * q;
            φ = (p - 1) * (q - 1);
            e = SimpleNumbersHelper.GetSimpleNumberFast(Randomizer.GetBadRandomLong(10000, 100000));
            d = MathHelper.GetInverseByMod(e, φ);
        }

        public RSA64(RSAPublicKey key)
        {
            d = key.D;
            n = key.N;
        }

        public RSA64(RSAPrivateKey key)
        {
            e = key.E;
            n = key.N;
        }

        public RSAPrivateKey GetPrivateKey()
        {
            if (n == 0)
            {
                return null;
            }

            return new RSAPrivateKey
            {
                E = e,
                N = n
            };
        }

        public RSAPublicKey GetPublicKey()
        {
            return new RSAPublicKey
            {
                D = d,
                N = n
            };
        }

        public BigInteger Encrypt(ulong message)
        {
            if (e == 0)
            {
                throw new Exception("Private key is absence");
            }

            return BigInteger.ModPow(message, e, n);
        }

        public ulong Decrypt(BigInteger message)
        {
            if (d == 0)
            {
                throw new Exception("Public key is absence");
            }

            var decrypted = BigInteger.ModPow(message, d, n);
            ulong.TryParse(decrypted.ToString(), out var result);
            return result;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var testFileOriginPath = @"D:\AESTEST\RSATESTOrigin.txt";
            var testFileFakePath = @"D:\AESTEST\RSATESTRepalcementByOneByte.txt";

            var originData = File.ReadAllBytes(testFileOriginPath);
            var fakeData = File.ReadAllBytes(testFileFakePath);

            var aesHash = new AESHASH64();
            var rsa = new RSA64();
            var privateKey = rsa.GetPrivateKey();
            var publicKey = rsa.GetPublicKey();

            var rsaSignatureManager = new RSASignatureManager();
            var signedResult = rsaSignatureManager.GetSignedBytes(privateKey, originData);

            Console.WriteLine("          Actual data: " + Encoding.ASCII.GetString(originData));
            Console.WriteLine("          Actual hash: " + aesHash.GetLongHash(originData));
            Console.WriteLine("     Actual signature: " + signedResult.Signature);
            Console.WriteLine("Verificiation success: " + rsaSignatureManager.Verify(publicKey, signedResult));

            signedResult.Data = fakeData;
            Console.WriteLine("            Fake data: " + Encoding.ASCII.GetString(fakeData));
            Console.WriteLine("            Fake hash: " + aesHash.GetLongHash(fakeData));
            Console.WriteLine("       Fake signature: " + rsaSignatureManager.GetSignedBytes(privateKey, fakeData).Signature);
            Console.WriteLine("Verificiation success: " + rsaSignatureManager.Verify(publicKey, signedResult));
        }
    }
}
