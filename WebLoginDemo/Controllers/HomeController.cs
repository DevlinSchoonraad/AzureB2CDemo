using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace WebLoginDemo.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        // Secure action
        [Authorize(Roles = "SuperUsers")]
        public async Task<ActionResult> Claims()
        {
            Claim displayName = ClaimsPrincipal.Current.FindFirst(ClaimsPrincipal.Current.Identities.First().NameClaimType);
            ViewBag.DisplayName = displayName != null ? displayName.Value : string.Empty;

            var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext
                as System.IdentityModel.Tokens.BootstrapContext;

            HttpClient client = new HttpClient();
            string url = "https://localhost:44348/api/values/";

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);

            // Add the token acquired from ADAL to the request headers
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bootstrapContext.Token);
            HttpResponseMessage response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();

            ViewBag.Message = await response.Content.ReadAsStringAsync();

            return View();
        }
    }
}