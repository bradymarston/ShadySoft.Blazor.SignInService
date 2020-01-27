using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.SignInService
{
    public interface ISignInService
    {
        Task RefreshSignInAsync(string userName);
        Task<SignInResult> SignInAsync(Credentials credentials, bool lockoutOnFailure = true);
        Task SignOutAsync();
    }
}