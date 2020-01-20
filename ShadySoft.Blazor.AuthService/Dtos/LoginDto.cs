using System;
using System.Collections.Generic;
using System.Text;

namespace ShadySoft.Blazor.AuthService.Dtos
{
    internal class LoginDto
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public DateTime ExpirationUtc { get; set; }

        public static LoginDto FromCredentials(Credentials credentials, DateTime expirationUtc)
        {
            return new LoginDto()
            {
                UserName = credentials.UserName,
                Password = credentials.Password,
                RememberMe = credentials.RememberMe,
                ExpirationUtc = expirationUtc
            };
        }
    }
}
