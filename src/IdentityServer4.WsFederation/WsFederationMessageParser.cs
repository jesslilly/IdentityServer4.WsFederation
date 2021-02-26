using System.Net;
using Microsoft.IdentityModel.Protocols.WsFederation;

namespace IdentityServer4.WsFederation
{
    public static class WsFederationMessageParser
    {
        public static WsFederationMessage GetSignInRequestMessage(string encodedUrl)
        {
            var decodedUrl = WebUtility.UrlDecode(encodedUrl);

            if (!decodedUrl.Contains("?")) return null;
            var query = decodedUrl.Split(new[] { '?' }, 2)[1];

            WsFederationMessage message = WsFederationMessage.FromQueryString(query);
            if (message.IsSignInMessage)
                return message;
            return null;
        }
    }
}