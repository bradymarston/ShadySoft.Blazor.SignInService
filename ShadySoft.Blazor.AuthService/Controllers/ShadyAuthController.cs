using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ShadySoft.Blazor.AuthService.Dtos;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ShadyAuthController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<ShadyAuthController> _logger;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private const int responseTimeoutInSeconds = 5;

        public ShadyAuthController(SignInManager<IdentityUser> signInManager, ILogger<ShadyAuthController> logger, IDataProtectionProvider dataProtectionProvider)
        {
            _signInManager = signInManager;
            _logger = logger;
            _dataProtectionProvider = dataProtectionProvider;
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

            var result = await _signInManager.PasswordSignInAsync(loginModel.UserName, loginModel.Password, loginModel.RememberMe, lockoutOnFailure: true);
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

        [HttpGet("test")]
        public IActionResult Test()
        {
            return Ok("Success");
        }

        private string BuildEncodedAuthResponse(string result)
        {
            var response = new AuthResponseDto() { Result = result, ExpirationUtc = DateTime.UtcNow + TimeSpan.FromSeconds(responseTimeoutInSeconds) };

            var protector = _dataProtectionProvider.CreateProtector("response");

            return protector.Protect(JsonSerializer.Serialize(response));
        }
    }
}
