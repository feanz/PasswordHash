using System;
using System.Linq;

namespace PasswordHash
{
    /// <summary>
    /// The default crypto class uses the Crypto class but set some sensible defaults for hashing iteration
    /// </summary>
    public class DefaultCrypto
    {
        private const char PasswordHashingIterationCountSeparator = '.';

        /* =======================
        * HASHED PASSWORD FORMATS
        * =======================
        * 
        * Version 0:
        * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
        * (See also: SDL crypto guidelines v5.1, Part III)
        * Format: { 0x00, salt, subkey }
        */
        public string HashPassword(string password, int iterations = -1)
        {
            var count = iterations;
            if (count <= 0)
            {
                count = GetIterationsFromYear(GetCurrentYear());
            }
            var result = Crypto.HashPassword(password, count);
            return EncodeIterations(count) + PasswordHashingIterationCountSeparator + result;
        }

        public bool VerifyHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword.Contains(PasswordHashingIterationCountSeparator))
            {
                var parts = hashedPassword.Split(PasswordHashingIterationCountSeparator);
                if (parts.Length != 2) return false;

                int count = DecodeIterations(parts[0]);
                if (count <= 0) return false;

                hashedPassword = parts[1];

                return Crypto.VerifyHashedPassword(hashedPassword, password, count);
            }
            else
            {
                return Crypto.VerifyHashedPassword(hashedPassword, password);
            }
        }

        public int DecodeIterations(string prefix)
        {
            int val;
            if (Int32.TryParse(prefix, System.Globalization.NumberStyles.HexNumber, null, out val))
            {
                return val;
            }
            return -1;
        }

        // from OWASP : https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
        const int StartYear = 2000;
        const int StartCount = 1000;
        public int GetIterationsFromYear(int year)
        {
            if (year > StartYear)
            {
                var diff = (year - StartYear) / 2;
                var mul = (int)Math.Pow(2, diff);
                int count = StartCount * mul;
                // if we go negative, then we wrapped (expected in year ~2044). 
                // Int32.Max is best we can do at this point
                if (count < 0) count = Int32.MaxValue;
                return count;
            }
            return StartCount;
        }

        public string EncodeIterations(int count)
        {
            return count.ToString("X");
        }

        public virtual int GetCurrentYear()
        {
            return DateTime.Now.Year;
        }
    }
}