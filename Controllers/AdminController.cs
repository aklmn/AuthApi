using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthApi.Services; 
namespace AuthApi.Controllers;

[Route("api/admin")]
[ApiController]
[Authorize(Roles = "Admin")]   // Semua endpoint di controller ini hanya boleh diakses Admin
public class AdminController : ControllerBase
{
    private readonly IAdminService _adminService;

    public AdminController(IAdminService adminService)
    {
        _adminService = adminService;
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _adminService.GetAllUsersAsync();
        return Ok(users);
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        var result = await _adminService.CreateUserAsync(request);
        if (!result.Success)
            return BadRequest(result);

        return Ok(result);
    }

    [HttpDelete("users/{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var result = await _adminService.DeleteUserAsync(id);
        if (!result.Success)
            return NotFound(result);

        return Ok(result);
    }
}