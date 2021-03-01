using System;
using System.Net;
using Microsoft.IdentityModel.Protocols.WsFederation;

namespace IdentityServer4.WsFederation
{
    public static class WsFederationMessageParser
    {
        public static WsFederationMessage GetSignInRequestMessage(string encodedUrl)
        {
            var decodedUrl = WebUtility.UrlDecode(encodedUrl);
            // Fix: Add dummy.com host so Uri can properly parse out the query string.
            var uri = new Uri("https://dummy.com" + decodedUrl);
            WsFederationMessage message = WsFederationMessage.FromUri(uri);;
            if (message.IsSignInMessage)
                return message;
            return null;
        }
    }
}