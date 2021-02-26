using Xunit;

namespace IdentityServer4.WsFederation.Tests
{
    public class WsFederationMessageParserTests
    {
        [Fact]
        public void GetSignInRequestMessage_parses_url_query_correctly()
        {
            var encodedUrl = "%2Fwsfederation%3Fwtrealm%3Drealm%26wa%3Dwsignin1.0%26wreply%3Dhttps%253A%252F%252Flocalhost%253A44310%252Fsignin-wsfed%26wctx%3DCfDJ8N3n";
            var message = WsFederationMessageParser.GetSignInRequestMessage(encodedUrl);
            Assert.Equal("realm",message.Wtrealm);
            Assert.Equal("wsignin1.0",message.Wa);
            Assert.Equal("https://localhost:44310/signin-wsfed",message.Wreply);
            Assert.Equal("CfDJ8N3n",message.Wctx);
        }

        [Fact]
        public void GetSignInRequestMessage_empty_query_returns_null()
        {
            var encodedUrl = "%2Fwsfederation%3F";
            var message = WsFederationMessageParser.GetSignInRequestMessage(encodedUrl);
            Assert.Null(message);
        }

        [Fact]
        public void GetSignInRequestMessage_no_query_returns_null()
        {
            var encodedUrl = "%2Fwsfederation";
            var message = WsFederationMessageParser.GetSignInRequestMessage(encodedUrl);
            Assert.Null(message);
        }
    }
}
