using AuthorizationAPI.Data;
using AuthorizationAPI.DTOs;
using AuthorizationAPI.Models;
using AuthorizationAPI.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthorizationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly ITokenService _tokenService;
        
        public AuthController(UserManager<ApplicationUser>userManager, ApplicationDbContext context, ITokenService tokenService)
        {
            _userManager = userManager;
            _context = context;
            _tokenService = tokenService;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO dto)
        {
            var user = new ApplicationUser
            {
                UserName = dto.Username,
                Email = dto.Email,
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            return Ok(new {Message = "User registered successfully." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO dto) 
        {
            var user = await _userManager.Users.Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
            {
                return Unauthorized(new { Message = "Invalid email or password." });
            }
            var roles = await _userManager.GetRolesAsync(user);
            var accessToken = _tokenService.CreateAccessToken(user, roles);
            var refreshToken = _tokenService.CreateRefreshToken(GetIpAddress());

            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
            return Ok(new TokenResponseDTO(accessToken, refreshToken.Token));
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestDTO dto)
        {
            var refreshToken = dto.RefreshToken;
            var user = await _userManager.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == refreshToken));

            if (user == null)
            {
                return Unauthorized(new { Message = "Invalid refresh token"});
            }

            var existingToken = user.RefreshTokens.Single(t=>t.Token == refreshToken);
            if (!existingToken.isActive) 
            {
                return Unauthorized(new { Message = "Refresh Token is inactive" });
            }
            existingToken.Revoked = DateTime.UtcNow;
            existingToken.RevokedByIp = GetIpAddress();

            var newRefreshToken = _tokenService.CreateRefreshToken(GetIpAddress());
            existingToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);

            await _userManager.UpdateAsync(user);

            //Generate new access token
            var roles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _tokenService.CreateAccessToken(user, roles);

            return Ok(new TokenResponseDTO(newAccessToken, newRefreshToken.Token));
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] TokenRequestDTO dto)
        {
            var token = dto.RefreshToken;
            var user = await _userManager.Users
                .Include(u=> u.RefreshTokens)
                .SingleOrDefaultAsync(u=>u.RefreshTokens.Any(t=>t.Token == token));

            if(user == null)
            {
                return NotFound();
            }

            var existing = user.RefreshTokens.Single(t => t.Token == token);
            if (!existing.isActive)
            {
                return BadRequest(new {Message = "This token is already revoked."});
            }
            existing.Revoked = DateTime.UtcNow;
            existing.RevokedByIp = GetIpAddress();

            await _userManager.UpdateAsync(user);
            return Ok(new { Message = "Token revoked successfully" });
        }
        private string GetIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-For"].ToString();
            }
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

    }
}
