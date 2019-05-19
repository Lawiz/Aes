using System;
using System.Collections.Generic;

namespace RSADigitalSignature
{
    public static class SimpleNumbersHelper
    {
        public static int GetSimpleNumber(int lessThan)
        {
            var simpleNumbers = new List<int>();

            for (int i = 2; i < lessThan; i++)
            {
                if (IsSimple(simpleNumbers, i))
                {
                    simpleNumbers.Add(i);
                }
            }

            return simpleNumbers.Count > 0 ? simpleNumbers[simpleNumbers.Count - 1] : 1;
        }

        public static ulong GetSimpleNumberFast(ulong lessThan)
        {
            for (ulong i = lessThan - 1; i > 0; i--)
            {
                if (IsSimple(i))
                {
                    return i;
                }
            }

            return 1;
        }

        public static bool IsSimple(ulong number)
        {
            var cycleEnd = Math.Sqrt(number) + 1;
            for (ulong i = 2; i < cycleEnd; i++)
            {
                if (number % i == 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsSimple(List<int> simpleNumbers, int number)
        {
            for (int j = 0; j < simpleNumbers.Count; j++)
            {
                if (number % simpleNumbers[j] == 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
