using AuthorizationAPI.DTOs;
using AuthorizationAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public RoleController(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto dto)
        {
            if (await _roleManager.RoleExistsAsync(dto.RoleName))
            {
                return BadRequest($"Role '{dto.RoleName}' already exists.");
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(dto.RoleName));
            if (!result.Succeeded) 
            {
                return BadRequest(result.Errors);
            }
            return Ok($"Role '{dto.RoleName}' created successfully.");
        }
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleDTO dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return NotFound($"User with email '{dto.Email}' not found.");
            }

            var result = await _userManager.AddToRoleAsync(user, dto.RoleName);
            if (!result.Succeeded) 
            {
                return BadRequest(result.Errors);
            }
            return Ok($"Role '{dto.RoleName}' assigned to user '{dto.Email}' successfully");
        }
    }
}
