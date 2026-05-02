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
        root.Add(CaCommand.Build());
        root.Add(ServerCommand.Build());
        root.Add(SmimeCommand.Build());
        root.Add(MiscCommands.BuildTestPfxCommand());
        root.Add(MiscCommands.BuildExportCommand());
        root.Add(MiscCommands.BuildSshCommand());
        root.Add(MiscCommands.BuildGpgCommand());
        root.Add(MiscCommands.BuildVersionCommand());

        try
        {
            return root.Parse(args).Invoke();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 1;
        }
    }
}
