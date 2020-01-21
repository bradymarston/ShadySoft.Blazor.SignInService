using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace ShadySoft.Blazor.SignInService.Interfaces
{
    public interface IUserServiceAccessor
    {
        Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
        Task RefreshSignInAsync(string userName);
        Task SignOutAsync();
    }
}