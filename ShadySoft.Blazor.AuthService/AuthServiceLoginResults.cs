using System;
using System.Collections.Generic;
using System.Text;

namespace ShadySoft.Blazor.SignInService
{
    internal class AuthServiceLoginResults
    {
        public const string Succeeded = "Succeeded";
        public const string Failed = "Failed";
        public const string RequiresTwoFactor = "RequiresTwoFactor";
        public const string IsLockedOut = "IsLockedOut";
        public const string IsNotAllowed = "IsNotAllowed";
    }
}
