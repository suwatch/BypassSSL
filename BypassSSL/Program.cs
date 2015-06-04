using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace BypassSSL
{
    class Program
    {
        static X509Certificate2 _wildcardWAWSCert = null;

        static void Main(string[] args)
        {
            try
            {
                CahceWildcardCert();

                HttpGet("https://davidebbo.com/");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static void CahceWildcardCert()
        {
            var request = (HttpWebRequest)WebRequest.Create("https://suwatbodin.azurewebsites.net/");
            request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                var verified = sslPolicyErrors == SslPolicyErrors.None;
                if (!verified)
                {
                    return false;
                }

                _wildcardWAWSCert = new X509Certificate2(certificate);
                return true;
            };

            using (var response = request.GetResponse())
            {
                // no-op
            }
        }

        static void HttpGet(string uri)
        {
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                var verified = sslPolicyErrors == SslPolicyErrors.None;
                if (verified)
                {
                    return true;
                }

                // only name mismatch but check if it is antares widecard
                if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                {
                    var sslCert = new X509Certificate2(certificate);
                    if (sslCert.Thumbprint == _wildcardWAWSCert.Thumbprint)
                    {
                        return true;
                    }
                }

                return false;
            };

            using (var response = request.GetResponse())
            {
                // no-op
            }
        }
    }
}
