// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Soverance.Certifactory.Scan.Risk;
using Xunit;

namespace Certifactory.Tests.Scan.Risk;

public class RiskGradeTests
{
    [Theory]
    [InlineData(0, 'A')]
    [InlineData(20, 'A')]
    [InlineData(20.1, 'B')]
    [InlineData(40, 'B')]
    [InlineData(55, 'C')]
    [InlineData(80, 'D')]
    [InlineData(80.1, 'F')]
    [InlineData(100, 'F')]
    public void For_maps_score_to_grade_band(double score, char expected)
    {
        RiskGrade.For(score).Should().Be(expected);
    }

    [Fact]
    public void Label_describes_the_grade()
    {
        RiskGrade.Label('F').Should().Be("Critical");
        RiskGrade.Label('A').Should().Be("Low");
    }
}
