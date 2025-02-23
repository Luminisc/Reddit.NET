﻿using Reddit.AuthTokenRetriever;
using Reddit.AuthTokenRetriever.EventArgs;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AuthTokenRetriever
{
    class Program
    {
        // Change this to the path to your local web browser.  --Kris
        public const string BROWSER_PATH = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

        static void Main(string[] args)
        {
            int port = 8080;
            if (args.Length > 0)
            {
                if (!int.TryParse(args[0], out port))
                {
                    Console.WriteLine("Reddit.NET OAuth Token Retriever");
                    Console.WriteLine("Created by Kris Craig");

                    Console.WriteLine();

                    Console.WriteLine("Usage:  AuthTokenRetriever [port] [App ID [App Secret]]");

                    Environment.Exit(Environment.ExitCode);
                }
            }

            string appId = (args.Length >= 2 ? args[1] : null);
            string appSecret = (args.Length >= 3 ? args[2] : null);

            // If appId and appSecret are unspecified, use guided mode.  --Kris
            if (string.IsNullOrWhiteSpace(appId) && string.IsNullOrWhiteSpace(appSecret))
            {
                if (string.IsNullOrWhiteSpace(appId))
                {
                    Console.Write("App ID: ");
                    appId = Console.ReadLine();
                }

                Console.Write("App Secret (leave blank for 'installed'-type apps): ");
                appSecret = Console.ReadLine();

                Console.WriteLine();
                Console.WriteLine("** IMPORTANT:  Before you proceed any further, make sure you are logged into Reddit as the user you wish to authenticate! **");
                Console.WriteLine();

                Console.WriteLine("In the next step, a browser window will open and you'll be taken to Reddit's app authentication page.  Press any key to continue....");
                Console.ReadKey();

                Console.Clear();
            }

            // Create a new instance of the auth token retrieval library.  --Kris
            AuthTokenRetrieverLib authTokenRetrieverLib = new AuthTokenRetrieverLib(appId, port, appSecret: appSecret);
            //AuthTokenRetrieverLib authTokenRetrieverLib = new AuthTokenRetrieverLib(appId, appSecret, port); // Deprecated as of 5.0.1.  --Kris

            authTokenRetrieverLib.AuthSuccess += C_AuthSuccess;
            authTokenRetrieverLib.OnException += OnException;

            // Start the callback listener.  --Kris
            authTokenRetrieverLib.AwaitCallback(generateLocalOutput: true, showGenericMessage: true);

            // Open the browser to the Reddit authentication page.  Once the user clicks "accept", Reddit will redirect the browser to localhost:8080, where AwaitCallback will take over.  --Kris
            OpenBrowser(authTokenRetrieverLib.AuthURL());

            Console.WriteLine("Awaiting Reddit callback -OR- press any key to abort....");

            Console.ReadKey();  // Hit any key to exit.  --Kris

            authTokenRetrieverLib.StopListening();

            Console.WriteLine("Token retrieval utility terminated.");
        }

        public static void OpenBrowser(string authUrl = "about:blank")
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    ProcessStartInfo processStartInfo = new ProcessStartInfo(authUrl);
                    Process.Start(processStartInfo);
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    ProcessStartInfo processStartInfo = new ProcessStartInfo(BROWSER_PATH)
                    {
                        Arguments = authUrl
                    };
                    Process.Start(processStartInfo);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // For OSX run a separate command to open the web browser as found in https://brockallen.com/2016/09/24/process-start-for-urls-on-net-core/
                Process.Start("open", authUrl);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // Similar to OSX, Linux can (and usually does) use xdg for this task.
                Process.Start("xdg-open", authUrl);
            }
        }

        // Consume the success event when the token is retrieved.  --Kris
        public static void C_AuthSuccess(object sender, AuthSuccessEventArgs e)
        {
            Console.Clear();

            Console.WriteLine("Token retrieval successful!");

            Console.WriteLine();

            Console.WriteLine("Access Token: " + e.AccessToken);
            Console.WriteLine("Refresh Token: " + e.RefreshToken);

            Console.WriteLine();

            Console.WriteLine("Press any key to exit....");
        }

        // Show error message if we got error while receiving data from reddit.  --Alexander Romanenko
        public static void OnException(object sender, ExceptionEventArgs e)
        {
            Console.Clear();

            Console.WriteLine("Token retrieval failed!");

            Console.WriteLine();

            Console.WriteLine($"Message: {e.Message}");
            Console.WriteLine($"Exception message: {e.Exception.Message}");
            Console.WriteLine($"Exception stacktrace:{Environment.NewLine}{e.Exception.StackTrace}");

            Console.WriteLine();

            Console.WriteLine("Press any key to exit....");
        }
    }
}
