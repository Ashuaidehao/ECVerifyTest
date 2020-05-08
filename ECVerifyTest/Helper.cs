using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace ECVerifyTest
{
    public static class Helper
    {


        public static byte[] HexToBytes(this string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                return Array.Empty<byte>();
            if (hexString.Length % 2 == 1)
                throw new FormatException();
            byte[] result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = byte.Parse(hexString.Substring(i * 2, 2), NumberStyles.AllowHexSpecifier);
            return result;
        }
    }
}
