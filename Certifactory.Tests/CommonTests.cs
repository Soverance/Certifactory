using FluentAssertions;
using Soverance.Certifactory;
using Xunit;

namespace Certifactory.Tests;

public class CommonTests
{
    [Fact]
    public void GetRandomByteArray_returns_high_entropy_bytes()
    {
        // generate 1000 20-byte arrays. with CSPRNG, no two should collide.
        // with System.Random seeded by time-of-day, rapid successive calls
        // can collide — this test would fail on the old impl in a tight loop.
        var seen = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            byte[] b = Common.GetRandomByteArray(20);
            string key = Convert.ToHexString(b);
            seen.Add(key).Should().BeTrue("each call should produce unique bytes");
        }
    }

    [Fact]
    public void GetRandomByteArray_returns_requested_length()
    {
        Common.GetRandomByteArray(16).Should().HaveCount(16);
        Common.GetRandomByteArray(32).Should().HaveCount(32);
    }
}
