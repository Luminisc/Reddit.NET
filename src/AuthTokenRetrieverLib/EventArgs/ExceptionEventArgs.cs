using System;

namespace Reddit.AuthTokenRetriever.EventArgs
{
    public class ExceptionEventArgs
    {
        public Exception Exception { get; set; } 

        public string Message { get; set; }
    }
}
