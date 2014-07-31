using System;
using System.Diagnostics;
using Xunit;

namespace PasswordHash
{
    public class PasswordHashTests
    {
        [Fact]
        public void Can_verify_hashed_password()
        {
            var sut = new DefaultCrypto();

            var password = "password";
            var hash = sut.HashPassword(password);

            var actual = sut.VerifyHashedPassword(hash, password);

            Assert.True(actual);
        }

        [Fact]
        public void Verify_return_false_for_invalid_password()
        {
            var sut = new DefaultCrypto();

            var password = "password";
            var invalid = sut.HashPassword("invalid");

            var actual = sut.VerifyHashedPassword(invalid, password);

            Assert.False(actual);
        }

        [Fact]
        public void Time_test_hash()
        {
            var sut = new DefaultCrypto();

            var password = "password";
            var stopwatch = new Stopwatch();
            
            stopwatch.Start();
            sut.HashPassword(password, 1000);
            stopwatch.Stop();

            var first = stopwatch.Elapsed;

            stopwatch.Start();
            sut.HashPassword(password, 128000);
            stopwatch.Stop();

            var second = stopwatch.Elapsed;

            Console.WriteLine(first);
            Console.WriteLine(second);
            Assert.True(second > first);
        }
    }
}