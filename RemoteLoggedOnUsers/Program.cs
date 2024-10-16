using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace RemoteLoggedOnUsers
{
    internal class Program
    {



        static void Main(string[] args)
        {


            string domain = string.Empty;
            string username = string.Empty;
            string password = string.Empty;
            string target = string.Empty;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-d":
                        if (i + 1 < args.Length)
                            domain = args[++i];
                        break;
                    case "-u":
                        if (i + 1 < args.Length)
                            username = args[++i];
                        break;
                    case "-p":
                        if (i + 1 < args.Length)
                            password = args[++i];
                        break;
                    case "-t":
                        if (i + 1 < args.Length)
                            target = args[++i];
                        break;
                }
            }


            if (args.Length == 0)
            {
                Console.WriteLine("\n[!] Please provide a target to connect to!");
                Console.WriteLine("[!] RemoteLoggedOnUsers.exe -t <target IP or fqdn>\n");
                return;
            }
           


            if (!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
            { 
                ConnectWithCreds(username, password, domain, target);
            }
            else

                ConnectWithoutCreds(target);





        }

        public static void ConnectWithoutCreds(string target)
        {
            Console.WriteLine($"\n[*] Running in the users context");
            Console.WriteLine($"[*] Attempting to enumerate logged on users on {target}");
            

            var users = new Dictionary<string, string>();

            //Connect to winreg named pipe and trigger RemoteRegistry Service to start.
            var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(Microsoft.Win32.RegistryHive.Users, target);
            var sidRegex = new Regex(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);

            foreach (var subkey in reg.GetSubKeyNames())
            {
                if (sidRegex.IsMatch(subkey))
                {
                    var sid = new SecurityIdentifier(subkey);
                    var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    users.Add(subkey, ntAccount.Value);
                }
            }

            Console.WriteLine(users.Count == 0 ? "\n[!] No users found!" : $"\n[*] Successfully enumerated {users.Count} users!");
            foreach (var user in users)
            {
                Console.WriteLine($"\t[+] SID: {user.Key}, User: {user.Value}");

            }
            Console.WriteLine("___________________________________________\n");
        }



        public static void ConnectWithCreds(string username, string password, string domain, string target)
        {
            Console.WriteLine($"\n[*] Running with given credentials from {username}");

            IntPtr tokenHandle = IntPtr.Zero;
            try
            {

                bool success = LogonUser(username, domain, password, 2, 0, out tokenHandle);
                if (!success)
                {
                    Console.WriteLine("[-] LogonUser failed with error code: " + Marshal.GetLastWin32Error());
                    Console.WriteLine("___________________________________________\n");
                    return;
                }


                using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(tokenHandle))
                {
                    Console.WriteLine($"[*] Attempting to enumerate logged on users on {target}");

                    var users = new Dictionary<string, string>();

                    using (var namedPipeClientStream = new NamedPipeClientStream(target, "winreg"))
                    {
                        try
                        {
                            namedPipeClientStream.Connect(5000);
                        }
                        catch
                        {
                            Console.WriteLine("[-] Failed to connect to named pipe.");
                            return;
                        }

                        if (!namedPipeClientStream.IsConnected) return;

                        // Console.WriteLine("[*] Successfully connected to winreg named pipe.\n");

                        var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(Microsoft.Win32.RegistryHive.Users, target);
                        var sidRegex = new Regex(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);

                        foreach (var subkey in reg.GetSubKeyNames())
                        {
                            if (sidRegex.IsMatch(subkey))
                            {
                                var sid = new SecurityIdentifier(subkey);
                                var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                                users.Add(subkey, ntAccount.Value);
                            }
                        }
                    }

                    Console.WriteLine(users.Count == 0 ? "[!] No users found!" : $"\n[*] Successfully enumerated {users.Count} users!");
                    foreach (var user in users)
                    {
                        Console.WriteLine($"\t[+] SID: {user.Key}, User: {user.Value}");
                    }

                    Console.WriteLine("___________________________________________\n");
                }
            }

            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }
        }





        //DLL Import for connection with given user

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
                                    int dwLogonType, int dwLogonProvider, out IntPtr phToken);


        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);
    }
}
