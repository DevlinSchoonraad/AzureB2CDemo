using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(WebServiceDemo.Startup))]

namespace WebServiceDemo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}