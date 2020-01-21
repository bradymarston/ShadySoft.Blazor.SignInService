using System;
using System.Collections.Generic;
using System.Text;

namespace ShadySoft.Blazor.SignInService.Dtos
{
    internal class AuthResponseDto
    {
        public string Result { get; set; }
        public DateTime ExpirationUtc { get; set; }


    }
}
