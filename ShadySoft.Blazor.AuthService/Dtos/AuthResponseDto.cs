using System;
using System.Collections.Generic;
using System.Text;

namespace ShadySoft.Blazor.AuthService.Dtos
{
    internal class AuthResponseDto
    {
        public string Result { get; set; }
        public DateTime ExpirationUtc { get; set; }


    }
}
