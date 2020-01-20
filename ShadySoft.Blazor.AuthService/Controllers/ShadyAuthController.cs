using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ShadySoft.Blazor.SignInService.Dtos;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.SignInService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ShadyAuthController : ControllerBase
    {
        private readonly SignInManager<TUser> _signInManager;
        private readonly ILogger<ShadyAuthController> _logger;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly UserManager<TUser> _userManager;
        private const int responseTimeoutInSeconds = 60;

        public ShadyAuthController(SignInManager<TUser> signInManager, ILogger<ShadyAuthController> logger, IDataProtectionProvider dataProtectionProvider, UserManager<TUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _dataProtectionProvider = dataProtectionProvider;
            _userManager = userManager;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(string encodedLoginModel)
        {
            string errorMessage;
            string errorCode;

            var protector = _dataProtectionProvider.CreateProtector("login");
            string decodedLoginModel;
            LoginDto loginModel;

            try
            {
                decodedLoginModel = protector.Unprotect(encodedLoginModel);
            }
            catch (CryptographicException)
            {
                _logger.LogWarning("Invalid login data submitted");
                return BadRequest(AuthServiceLoginResults.Failed);
            }

            if (string.IsNullOrWhiteSpace(decodedLoginModel))
            {
                _logger.LogWarning("Invalid login data submitted");
                return BadRequest(AuthServiceLoginResults.Failed);
            }

            try
            {
                loginModel = JsonSerializer.Deserialize<LoginDto>(decodedLoginModel);
            }
            catch
            {
                _logger.LogWarning("Invalid login data submitted");
                return BadRequest(AuthServiceLoginResults.Failed);
            }

            if (loginModel.ExpirationUtc < DateTime.UtcNow)
            {
                _logger.LogWarning("Expired login data submitted");
                return BadRequest(AuthServiceLoginResults.Failed);
            }

            var result = await _signInManager.PasswordSignInAsync(loginModel.UserName, loginModel.Password, loginModel.RememberMe, loginModel.LockoutOnFailure);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                return Ok(BuildEncodedAuthResponse(AuthServiceLoginResults.Succeeded));
            }
            if (result.RequiresTwoFactor)
            {
                errorMessage = "Requires two factor authentication (not supported).";
                errorCode = AuthServiceLoginResults.RequiresTwoFactor;
            }
            else
            {
                if (result.IsLockedOut)
                {
                    errorMessage = "User account locked out.";
                    errorCode = AuthServiceLoginResults.IsLockedOut;
                }
                else
                {
                    if (result.IsNotAllowed)
                    {
                        errorMessage = "Account not confirmed.";
                        errorCode = AuthServiceLoginResults.IsNotAllowed;
                    }
                    else
                    {
                        errorMessage = "Invalid login attempt.";
                        errorCode = AuthServiceLoginResults.Failed;
                    }
                }
            }

            _logger.LogWarning(errorMessage);
            return BadRequest(BuildEncodedAuthResponse(errorCode));
        }

        [HttpPost("logout")]
        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            
            return Ok();
        }

        [HttpPost("referesh")]
        public async Task<IActionResult> RefreshSignIn(string encodedRefreshDto)
        {
            var protector = _dataProtectionProvider.CreateProtector("refesh");
            var decodedRefreshDto = protector.Unprotect(encodedRefreshDto);
            RefreshSignInDto refreshDto;
            try
            {
                refreshDto = JsonSerializer.Deserialize<RefreshSignInDto>(decodedRefreshDto);
            }
            catch (CryptographicException)
            {
                _logger.LogWarning("Invalid refresh sign in data submitted");
                return BadRequest();
            }

            if (refreshDto.ExpirationUtc < DateTime.UtcNow)
            {
                _logger.LogWarning("Expired refresh sign in data submitted");
                return BadRequest();
            }

            var user = await _userManager.FindByNameAsync(refreshDto.UserName);

            try
            {
                await _signInManager.RefreshSignInAsync(user);
            }
            catch
            {
                return BadRequest();
            }

            return Ok();
        }

        private string BuildEncodedAuthResponse(string result)
        {
            var response = new AuthResponseDto() { Result = result, ExpirationUtc = DateTime.UtcNow + TimeSpan.FromSeconds(responseTimeoutInSeconds) };

            var protector = _dataProtectionProvider.CreateProtector("response");

            return protector.Protect(JsonSerializer.Serialize(response));
        }
    }
}
