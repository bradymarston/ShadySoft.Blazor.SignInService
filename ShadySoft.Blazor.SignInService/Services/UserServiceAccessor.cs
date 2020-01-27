using Microsoft.AspNetCore.Identity;
using ShadySoft.Blazor.SignInService.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.SignInService.Services
{
    internal class UserServiceAccessor<TUser> : IUserServiceAccessor where TUser : class
    {
        private readonly SignInManager<TUser> _signInManager;
        private readonly UserManager<TUser> _userManager;

        public UserServiceAccessor(SignInManager<TUser> signInManager, UserManager<TUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure) => _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
        public Task SignOutAsync() => _signInManager.SignOutAsync();

        public async Task RefreshSignInAsync(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            await _signInManager.RefreshSignInAsync(user);
        }
    }
}
