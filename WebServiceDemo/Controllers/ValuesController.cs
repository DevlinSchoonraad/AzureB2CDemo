using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace WebServiceDemo.Controllers
{
    [Authorize]
    public class ValuesController : ApiController
    {
        public string Get()
        {
            var user = ClaimsPrincipal.Current.FindFirst("name").Value;

            return $"Hello {user}";
        }
    }
}
