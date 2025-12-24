using AuthorizationAPI.Models;

namespace AuthorizationAPI.Services
{
    public interface ITokenService
    {
        string CreateAccessToken(ApplicationUser user, IList<string> roles);
        RefreshToken CreateRefreshToken(string ipAddress);
    }
}
