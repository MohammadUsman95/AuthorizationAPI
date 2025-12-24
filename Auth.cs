namespace AuthorizationAPI.DTOs
{
    public record RegisterDTO(string Username, string Email, string Password);
    public record LoginDTO(string Email, string Password);
    public record TokenRequestDTO(string AccessToken, string RefreshToken);
    public record TokenResponseDTO(string AccessToken, string RefreshToken);
    public record AssignRoleDTO(string Email, string RoleName);
    public record CreateRoleDto(string RoleName);
}
