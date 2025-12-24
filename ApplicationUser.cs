using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public List<RefreshToken> RefreshTokens { get; set; } = new();
    }
}
