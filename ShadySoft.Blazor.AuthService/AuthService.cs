using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.JSInterop;
using ShadySoft.Blazor.AuthService.Dtos;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.AuthService
{
    public class AuthService
    {
        private readonly IHostEnvironmentAuthenticationStateProvider _serverAuthenticationStateProvider;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private readonly IUserStore<IdentityUser> _userStore;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IJSRuntime _jSRuntime;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private const int loginExpirationSeconds = 5;

        public AuthService(IHostEnvironmentAuthenticationStateProvider serverSuthenticationStateProvider,
                           IUserStore<IdentityUser> userStore,
                           UserManager<IdentityUser> userManager,
                           SignInManager<IdentityUser> signInManager,
                           IJSRuntime jSRuntime,
                           IDataProtectionProvider dataProtectionProvider)
        {
            _serverAuthenticationStateProvider = serverSuthenticationStateProvider;
            _userStore = userStore;
            _userManager = userManager;
            _signInManager = signInManager;
            _jSRuntime = jSRuntime;
            _dataProtectionProvider = dataProtectionProvider;
        }

        public Task<SignInResult> LoginAsync(Credentials credentials)
        {
            var loginDto = LoginDto.FromCredentials(credentials, DateTime.UtcNow + TimeSpan.FromSeconds(loginExpirationSeconds));
            var callback = new LoginCallback(loginDto, this);

            var protector = _dataProtectionProvider.CreateProtector("login");
            var encodedCredentials = protector.Protect(JsonSerializer.Serialize(loginDto));

            _jSRuntime.InvokeVoidAsync("shadyAuthHelpers.login", encodedCredentials, DotNetObjectReference.Create(callback));

            return callback.ResultSource.Task;
        }

        private async Task FinishServerLoginAsync(LoginDto loginDto, TaskCompletionSource<SignInResult> resultSource)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            _serverAuthenticationStateProvider.SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
            resultSource.SetResult(SignInResult.Success);
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

        internal class LoginCallback
        {
            private readonly AuthService _authService;

            public LoginCallback(LoginDto loginDto, AuthService authService)
            {
                Credentials = loginDto;
                _authService = authService;
            }

            public TaskCompletionSource<SignInResult> ResultSource { get; set; } = new TaskCompletionSource<SignInResult>();
            public LoginDto Credentials { get; }

            [JSInvokable]
            public void ClientLoginComplete(string encodedResponse)
            {
                var result = _authService.DecodeAuthResponse(encodedResponse);
                
                var signInResult = result switch
                {
                    AuthServiceLoginResults.Succeeded => SignInResult.Success,
                    AuthServiceLoginResults.RequiresTwoFactor => SignInResult.TwoFactorRequired,
                    AuthServiceLoginResults.IsLockedOut => SignInResult.LockedOut,
                    AuthServiceLoginResults.IsNotAllowed => SignInResult.NotAllowed,
                    _ => SignInResult.Failed,
                };

                if (signInResult.Succeeded)
                    _authService.FinishServerLoginAsync(Credentials, ResultSource);
                else
                    ResultSource.SetResult(signInResult);
            }
        }
    }
}