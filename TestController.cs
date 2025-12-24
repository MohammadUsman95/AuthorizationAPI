using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult Public()
        {
            return Ok("This is a public endpoint");
        }
        [Authorize]
        [HttpGet("protected")]
        public IActionResult Protected() 
        {
            return Ok("This is a protected endpoint. You are authorized.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult Admin()
        {
            return Ok("This is a admin endpoint. You are authorized as an admin");
        }

    }
}
