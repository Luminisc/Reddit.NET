using Reddit.AuthTokenRetriever.EventArgs;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using uhttpsharp;
using uhttpsharp.Listeners;
using uhttpsharp.RequestProviders;

namespace Reddit.AuthTokenRetriever
{
    public class AuthTokenRetrieverLib
    {
        /// <summary>
        /// Your Reddit App ID
        /// </summary>
        internal string AppId
        {
            get;
            private set;
        }

        /// <summary>
        /// Your Reddit App Secret (leave empty for installed apps)
        /// </summary>
        internal string AppSecret
        {
            get;
            private set;
        }

        /// <summary>
        /// The port to listen on for the callback (default: 8080)
        /// </summary>
        internal int Port
        {
            get;
            private set;
        }

        /// <summary>
        /// The address to bind for the callback (default: 127.0.0.1)
        /// </summary>
        internal string Host
        {
            get;
            private set;
        }

        /// <summary>
        /// The Redirect URI specified in your app settings on Reddit (default: https://localhost:(port)/Reddit.NET/oauthRedirect)
        /// </summary>
        internal string RedirectURI
        {
            get;
            private set;
        }

        internal HttpServer HttpServer
        {
            get;
            private set;
        }

        public string AccessToken
        {
            get;
            private set;
        }

        public string RefreshToken
        {
            get;
            private set;
        }

        public event EventHandler<AuthSuccessEventArgs> AuthSuccess;

        public event EventHandler<ExceptionEventArgs> OnException;

        /// <summary>
        /// Create a new instance of the Reddit.NET OAuth Token Retriever library.
        /// </summary>
        /// <param name="appId">Your Reddit App ID</param>
        /// <param name="port">The port to listen on for the callback (recommended: 8080)</param>
        /// <param name="host">The host to bind for the callback (default: 127.0.0.1)</param>
        /// <param name="redirectUri">The Redirect URI specified in your app settings on Reddit (default: https://(host):(port)/Reddit.NET/oauthRedirect)</param>
        /// <param name="appSecret">Your Reddit App Secret (leave empty for installed apps)</param>
        public AuthTokenRetrieverLib(string appId, int port, string host = null, string redirectUri = null, string appSecret = null)
        {
            AppId = appId;
            AppSecret = appSecret;
            Port = port;
            Host = host ?? IPAddress.Loopback.ToString();
            RedirectURI = redirectUri ?? "http://" + Host + ":" + Port.ToString() + "/Reddit.NET/oauthRedirect";
        }

        public void AwaitCallback(bool generateLocalOutput = false, bool showGenericMessage = false)
        {
            HttpServer?.Dispose();
            HttpServer = new HttpServer(new HttpRequestProvider());
            HttpServer.Use(new TcpListenerAdapter(new TcpListener(IPAddress.Parse(Host.Equals("localhost")
                    ? IPAddress.Loopback.ToString() : Host), Port)));

            HttpServer.Use((context, next) =>
            {
                string code = null;
                string state = null;
                try
                {
                    code = context.Request.QueryString.GetByName("code");
                    state = context.Request.QueryString.GetByName("state");  // This app formats state as:  AppId + ":" [+ AppSecret]
                }
                catch (KeyNotFoundException e)
                {
                    context.Response = new uhttpsharp.HttpResponse(HttpResponseCode.Ok, Encoding.UTF8.GetBytes("<b>ERROR:  No code and/or state received!</b>"), false);
                    var errorMessage = "ERROR:  Request received without code and/or state!";
                    OnException?.Invoke(this, new ExceptionEventArgs { Exception = e, Message = errorMessage });
                    throw new Exception(errorMessage);
                }

                try
                {
                    if (!string.IsNullOrWhiteSpace(code) && !string.IsNullOrWhiteSpace(state))
                    {
                        // Send request with code and JSON-decode the return for token retrieval.  --Kris
                        RestRequest restRequest = new RestRequest("/api/v1/access_token", Method.POST);

                        restRequest.AddHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(state)));
                        restRequest.AddHeader("Content-Type", "application/x-www-form-urlencoded");

                        restRequest.AddParameter("grant_type", "authorization_code");
                        restRequest.AddParameter("code", code);
                        restRequest.AddParameter("redirect_uri",
                            "http://" + Host + ":" + Port.ToString() + "/Reddit.NET/oauthRedirect");  // This must be an EXACT match in the app settings on Reddit!  --Kris

                        OAuthToken oAuthToken = JsonConvert.DeserializeObject<OAuthToken>(ExecuteRequest(restRequest));

                        // Set the token properties.  --Kris
                        AccessToken = oAuthToken.AccessToken;
                        RefreshToken = oAuthToken.RefreshToken;

                        // Fire the auth success event with the token in the event args.  --Kris
                        AuthSuccess?.Invoke(this, new AuthSuccessEventArgs { AccessToken = oAuthToken.AccessToken, RefreshToken = oAuthToken.RefreshToken });

                        // Generate the success page.  --Kris
                        string[] sArr = state.Split(':');
                        if (sArr == null || sArr.Length == 0)
                        {
                            var errorMessage = "State must consist of 'appId:appSecret'!";
                            var exception = new Exception("State must consist of 'appId:appSecret'!");
                            OnException?.Invoke(this, new ExceptionEventArgs { Exception = exception, Message = errorMessage });
                            throw exception;
                        }

                        string appId = sArr[0];
                        string appSecret = (sArr.Length >= 2 ? sArr[1] : null);

                        string html;

                        // I dont think enduser need any info about his tokens
                        if (!showGenericMessage)
                        {
                            using (Stream stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("AuthTokenRetrieverLib.Templates.Success.html"))
                            {
                                using (StreamReader streamReader = new StreamReader(stream))
                                {
                                    html = streamReader.ReadToEnd();
                                }
                            }

                            html = html.Replace("REDDIT_OAUTH_ACCESS_TOKEN", oAuthToken.AccessToken);
                            html = html.Replace("REDDIT_OAUTH_REFRESH_TOKEN", oAuthToken.RefreshToken);

                            // If enabled, output the token to a JSON file in the current directory.  --Kris
                            if (generateLocalOutput)
                            {
                                string tokenSavedHtml;
                                using (Stream stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("AuthTokenRetrieverLib.Templates.TokenSaved.html"))
                                {
                                    using (StreamReader streamReader = new StreamReader(stream))
                                    {
                                        tokenSavedHtml = streamReader.ReadToEnd();
                                    }
                                }

                                string fileExt = "." + appId + "." + (!string.IsNullOrWhiteSpace(appSecret) ? appSecret + "." : "") + "json";

                                string tokenPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar
                                    + "RDNOauthToken_" + DateTime.Now.ToString("yyyyMMddHHmmssffff") + fileExt;

                                File.WriteAllText(tokenPath, JsonConvert.SerializeObject(oAuthToken));

                                html = html.Replace("TOKEN_SAVED", tokenSavedHtml.Replace("LOCAL_TOKEN_PATH", tokenPath));
                            }
                            else
                            {
                                html = html.Replace("TOKEN_SAVED", "");
                            }
                        }
                        else
                        {
                            html = "<h1>Login successful!<br/>Please close browser to proceed with app.</h1>";
                        }

                        // Send the success page.  --Kris
                        context.Response = new uhttpsharp.HttpResponse(HttpResponseCode.Ok, Encoding.UTF8.GetBytes(html), false);
                    }
                }
                catch (Exception e)
                {
                    // if something went wrong we will not be able to get error without this try/catch, especially useful for mobile apps where console is not an option  --Alexander Romanenko
                    OnException?.Invoke(this, new ExceptionEventArgs { Exception = e, Message = "ERROR:  Unable to process request from reddit!" });
                    throw;
                }

                return Task.CompletedTask;
            });

            HttpServer.Start();
        }

        public void StopListening()
        {
            HttpServer?.Dispose();
        }

        public string AuthURL(string scope = "creddits%20modcontributors%20modmail%20modconfig%20subscribe%20structuredstyles%20vote%20wikiedit%20mysubreddits%20submit%20modlog%20modposts%20modflair%20save%20modothers%20read%20privatemessages%20report%20identity%20livemanage%20account%20modtraffic%20wikiread%20edit%20modwiki%20modself%20history%20flair")
        {
            return "https://www.reddit.com/api/v1/authorize?client_id=" + AppId + "&response_type=code"
                + "&state=" + AppId + ":" + AppSecret
                + "&redirect_uri=http://" + Host + ":" + Port.ToString() + "/Reddit.NET/oauthRedirect&duration=permanent"
                + "&scope=" + scope;
        }

        public string ExecuteRequest(RestRequest restRequest)
        {
            IRestResponse res = new RestClient("https://www.reddit.com").Execute(restRequest);
            if (res != null && res.IsSuccessful)
            {
                return res.Content;
            }
            else
            {
                Exception ex = new Exception("API returned non-success response.");

                ex.Data.Add("res", res);

                throw ex;
            }
        }
    }
}
