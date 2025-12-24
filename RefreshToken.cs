namespace AuthorizationAPI.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public string? CreatedByIp { get; set; }
        public DateTime Revoked { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }

        public bool isExpired => DateTime.UtcNow >= Expires;
        public bool isActive => Revoked == null && !isExpired;

        // foreignkey to applicationuser
        public string? UserId { get; set; } = string.Empty;
        public ApplicationUser User { get; set; } = null;
    }
}
