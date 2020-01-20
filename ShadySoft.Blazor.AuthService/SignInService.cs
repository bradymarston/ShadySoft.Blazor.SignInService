using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using ShadySoft.Blazor.SignInService.Dtos;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.SignInService
{
    public class SignInService<TUser> where TUser : class
    {
        private readonly IHostEnvironmentAuthenticationStateProvider _serverAuthenticationStateProvider;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private readonly IUserStore<TUser> _userStore;
        private readonly UserManager<TUser> _userManager;
        private readonly SignInManager<TUser> _signInManager;
        private readonly IJSRuntime _jSRuntime;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private const int loginExpirationSeconds = 60;

        public SignInService(IHostEnvironmentAuthenticationStateProvider serverSuthenticationStateProvider,
                           AuthenticationStateProvider authenticationStateProvider,
                           IUserStore<TUser> userStore,
                           UserManager<TUser> userManager,
                           SignInManager<TUser> signInManager,
                           IJSRuntime jSRuntime,
                           IServiceScopeFactory scopeFactory,
                           IDataProtectionProvider dataProtectionProvider)
        {
            _serverAuthenticationStateProvider = serverSuthenticationStateProvider;
            _authenticationStateProvider = authenticationStateProvider;
            _userStore = userStore;
            _userManager = userManager;
            _signInManager = signInManager;
            _jSRuntime = jSRuntime;
            _scopeFactory = scopeFactory;
            _dataProtectionProvider = dataProtectionProvider;
        }

        public Task<SignInResult> SignInAsync(Credentials credentials, bool lockoutOnFailure = true)
        {
            var loginDto = LoginDto.FromCredentials(credentials, lockoutOnFailure, DateTime.UtcNow + TimeSpan.FromSeconds(loginExpirationSeconds));
            var callback = new SignInCallback(loginDto, this);

            var protector = _dataProtectionProvider.CreateProtector("login");
            var encodedCredentials = protector.Protect(JsonSerializer.Serialize(loginDto));

            _jSRuntime.InvokeVoidAsync("shadyAuthHelpers.login", encodedCredentials, DotNetObjectReference.Create(callback));

            return callback.ResultSource.Task;
        }
        public Task SignOutAsync()
        {
            var callback = new SignOutCallback(this);

            _jSRuntime.InvokeVoidAsync("shadyAuthHelpers.logout", DotNetObjectReference.Create(callback));

            return callback.ResultSource.Task;
        }

        public Task RefreshSignInAsync(string userName)
        {
            var callback = new RefreshSignInCallback(userName, this);            

            var dto = new RefreshSignInDto() { UserName = userName, ExpirationUtc = DateTime.UtcNow + TimeSpan.FromSeconds(loginExpirationSeconds) };
            var protector = _dataProtectionProvider.CreateProtector("login");
            var encodedDto = protector.Protect(JsonSerializer.Serialize(dto));

            _jSRuntime.InvokeVoidAsync("shadyAuthHelpers.refresh", encodedDto, DotNetObjectReference.Create(callback));

            return callback.ResultSource.Task;
        }

        private async Task FinishServerSignInAsync(LoginDto loginDto, TaskCompletionSource<SignInResult> resultSource)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            _serverAuthenticationStateProvider.SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
            resultSource.SetResult(SignInResult.Success);
        }

        private void FinishServerSignOut(TaskCompletionSource<bool> resultSource)
        {
            _serverAuthenticationStateProvider.SetAuthenticationState(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
            resultSource.SetResult(true);
        }

        private async Task FinishServerRefreshSignInAsync(string userName, TaskCompletionSource<bool> resultSource)
        {
            var scope = _scopeFactory.CreateScope();

            var newUserManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
            var user = await newUserManager.FindByIdAsync(userName);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            _serverAuthenticationStateProvider.SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
            resultSource.SetResult(true);
        }

        private string DecodeAuthResponse(string encodedResponse)
        {
            var protector =_dataProtectionProvider.CreateProtector("response");

            var decodedResponse = protector.Unprotect(encodedResponse);

            var response = JsonSerializer.Deserialize<AuthResponseDto>(decodedResponse);

            if (response.ExpirationUtc < DateTime.UtcNow)
                throw new Exception("Attempt to use expired Auth response data.");

            return response.Result;
        }

        internal class SignInCallback
        {
            private readonly SignInService _signInService;

            public SignInCallback(LoginDto loginDto, SignInService signInService)
            {
                Credentials = loginDto;
                _signInService = signInService;
            }

            public TaskCompletionSource<SignInResult> ResultSource { get; set; } = new TaskCompletionSource<SignInResult>();
            public LoginDto Credentials { get; }

            [JSInvokable]
            public void ClientSignInComplete(string encodedResponse)
            {
                var result = _signInService.DecodeAuthResponse(encodedResponse);
                
                var signInResult = result switch
                {
                    AuthServiceLoginResults.Succeeded => SignInResult.Success,
                    AuthServiceLoginResults.RequiresTwoFactor => SignInResult.TwoFactorRequired,
                    AuthServiceLoginResults.IsLockedOut => SignInResult.LockedOut,
                    AuthServiceLoginResults.IsNotAllowed => SignInResult.NotAllowed,
                    _ => SignInResult.Failed,
                };

                if (signInResult.Succeeded)
                    _signInService.FinishServerSignInAsync(Credentials, ResultSource);
                else
                    ResultSource.SetResult(signInResult);
            }
        }

        internal class SignOutCallback
        {
            private readonly SignInService _signInService;

            public SignOutCallback(SignInService signInService)
            {
                _signInService = signInService;
            }
            public TaskCompletionSource<bool> ResultSource { get; set; } = new TaskCompletionSource<bool>();

            [JSInvokable]
            public void ClientSignOutComplete()
            {
                _signInService.FinishServerSignOut(ResultSource);
            }
        }
        internal class RefreshSignInCallback
        {
            private readonly SignInService _signInService;

            public RefreshSignInCallback(string userName, SignInService signInService)
            {
                _signInService = signInService;
                UserName = userName;
            }

            public string UserName { get; }

            public TaskCompletionSource<bool> ResultSource { get; set; } = new TaskCompletionSource<bool>();

            [JSInvokable]
            public void ClientRefreshSignInComplete(bool succeeded)
            {
                if (!succeeded)
                {
                    ResultSource.SetResult(false);
                    return;
                }

                _signInService.FinishServerRefreshSignInAsync(UserName, ResultSource);
            }
        }
    }
}