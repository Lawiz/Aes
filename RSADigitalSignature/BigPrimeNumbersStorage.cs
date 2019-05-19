using AESHash;
using System.Linq;
using System.Numerics;

namespace RSADigitalSignature
{
    public static class BigPrimeNumbersStorage
    {
        private static readonly BigInteger[] primes;

        static BigPrimeNumbersStorage()
        {
            var primesStrings = new string[]
            {
                "1298074214633706835075030044377087",
                "618970019642690137449562111",
                "162259276829213363391578010288127",
                "170141183460469231731687303715884105727",
                "19175002942688032928599",
                "1066340417491710595814572169",
                "19134702400093278081449423917",
                "900900900900990990990991",
                "909090909090909090909090909091",
                "10888869450418352160768000001",
                "265252859812191058636308479999999",
                "263130836933693530167218012159999999",
                "8683317618811886495518194401279999999 "
            };

            primes = primesStrings.Select(x => BigInteger.Parse(x)).ToArray();
        }

        public static BigInteger GetRandomPrime()
        {
            return primes[Randomizer.GetRandomInt(0, primes.Length)];
        }
    }
}
