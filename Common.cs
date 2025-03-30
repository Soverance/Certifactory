// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web;

public class Common
{
    public static string GetAssemblyVersion()
    {
        return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version!.ToString();
    }

    public static string GetBasePath()
    {
        string baseDir = "";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // the "old" ways of getting this path in standard .NET appear to be non-functional when deployed in a Core Linux environment
            // so for dotnet core, we'll get the actual process that invoked this function and gather it's file name, which can give us the root path
            using var processModule = System.Diagnostics.Process.GetCurrentProcess().MainModule;
            baseDir = Path.GetDirectoryName(processModule?.FileName)!;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // in windows environments we could use reflection to get the application base folder path
            // but we can also use easier functions such as "AppContext.BaseDirectory" or "AppDomain.CurrentDomain.BaseDirectory"
            baseDir = AppContext.BaseDirectory;
        }

        return baseDir;
    }

    public static byte[] GetRandomByteArray(int size)
    {
        Random rnd = new();
        byte[] b = new byte[size];
        rnd.NextBytes(b);
        Debug.WriteLine("[DEBUG] BYTE ARRAY = " + b);
        return b;
    }

    // Generates a random alphanumeric string
    // we use this for creating temporary folders for file uploads
    public static string RandomString(int length)
    {
        Random random = new Random();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }
}