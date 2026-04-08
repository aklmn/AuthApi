using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;
[Route("api/test")]
[ApiController]
[Authorize]
public class TestController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { message = "Anda sudah login! Ini data protected." });
}