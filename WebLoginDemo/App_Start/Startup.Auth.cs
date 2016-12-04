using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json.Linq;
using Owin;
using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Adal = Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WebLoginDemo
{
    public partial class Startup
    {
        // App config settings
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        // B2C policy identifiers
        public static string SignInPolicyId = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        // Graph API credentials
        public static string GraphClientId = ConfigurationManager.AppSettings["ida:GraphClientId"];
        public static string GraphClientSecret = ConfigurationManager.AppSettings["ida:GraphClientSecret"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // Configure OpenID Connect middleware for each policy
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(ProfilePolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignInPolicyId));
        }

        private OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            return new OpenIdConnectAuthenticationOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = String.Format(aadInstance, tenant, policy),
                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = clientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = AuthenticationFailed,
                    SecurityTokenValidated = AddRoles
                },
                Scope = "openid",
                ResponseType = "id_token",

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    SaveSigninToken = true
                },
            };
        }
        private async Task AddRoles(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> arg)
        {
            var context = new Adal.AuthenticationContext("https://login.microsoftonline.com/" + tenant);
            var clientCredentials = new Adal.ClientCredential(GraphClientId, GraphClientSecret);
            var token = await context.AcquireTokenAsync("https://graph.windows.net/", clientCredentials);

            var userId = arg.AuthenticationTicket.Identity.Claims
                .First(x => x.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier")
                .Value;

            HttpClient http = new HttpClient();
            string url = "https://graph.windows.net/b2ctestdes.onmicrosoft.com/users/" + userId + "/memberOf?api-version=1.6";

            // Append the access token for the Graph API to the Authorization header of the request by using the Bearer scheme.
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
            HttpResponseMessage response = await http.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStringAsync();

                dynamic groups = JObject.Parse(result);

                foreach (var group in groups.value)
                {
                    string groupName = group.displayName;

                    arg.AuthenticationTicket.Identity.AddClaim(
                        new Claim(ClaimTypes.Role, groupName));
                }
            }
        }

        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }
    }
}