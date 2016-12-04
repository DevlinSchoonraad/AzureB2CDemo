using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(WebLoginDemo.Startup))]

namespace WebLoginDemo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}