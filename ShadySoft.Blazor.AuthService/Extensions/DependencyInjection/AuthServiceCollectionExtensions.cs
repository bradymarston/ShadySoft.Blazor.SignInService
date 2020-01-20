using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using ShadySoft.Blazor.AuthService;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class AuthServiceCollectionExtensions
    {
        public static IdentityBuilder AddBlazorIdentity<TUser, TRole>(this IServiceCollection services) where TUser : class where TRole : class
        {
            services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
            services.AddScoped<IHostEnvironmentAuthenticationStateProvider>(sp => {
                var provider = (ServerAuthenticationStateProvider)sp.GetRequiredService<AuthenticationStateProvider>();
                return provider;
            });

            services.AddScoped<AuthService>();

            return services.AddIdentity<TUser, TRole>();
        }
    }
}
