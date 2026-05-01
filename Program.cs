// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System.CommandLine;
using Soverance.Certifactory.Commands;

class Program
{
    static int Main(string[] args)
    {
        var root = new RootCommand("Soverance Studios - Certifactory certificate generation utility.");
        root.Add(MiscCommands.BuildVersionCommand());
        root.Add(MiscCommands.BuildTestPfxCommand());
        root.Add(MiscCommands.BuildExportCommand());
        root.Add(MiscCommands.BuildSshCommand());
        root.Add(MiscCommands.BuildGpgCommand());
        return root.Parse(args).Invoke();
    }
}
