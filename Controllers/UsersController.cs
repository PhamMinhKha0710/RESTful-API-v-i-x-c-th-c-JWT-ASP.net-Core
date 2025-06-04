using JwtRestfulApi.Models;
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // This ensures all endpoints require authentication
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        // Public endpoints for all authenticated users

        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            // Get the current user's ID from the claims
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized(new { message = "User not authenticated" });
            }

            var user = _userService.GetById(userId);
            if (user == null)
            {
                return NotFound(new { message = "User not found" });
            }

            // Return user without sensitive data
            return Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Role
            });
        }

        [HttpGet("basic-info")]
        public IActionResult GetBasicInfo()
        {
            return Ok(new
            {
                message = "This is basic user information available to all authenticated users",
                timestamp = DateTime.Now,
                features = new[] { "Profile Access", "Data Updates", "Basic Reports" }
            });
        }

        // This endpoint is available only to the specific user or an admin
        [HttpGet("personal-data/{id}")]
        public IActionResult GetPersonalData(string id)
        {
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;

            // Check if the user is requesting their own data or is an admin
            if (currentUserId != id && userRole != "Admin")
            {
                return Forbid();
            }

            var user = _userService.GetById(id);
            if (user == null)
            {
                return NotFound(new { message = "User not found" });
            }

            // Simulate personal data retrieval
            return Ok(new
            {
                userId = user.Id,
                personalData = new
                {
                    username = user.Username,
                    email = user.Email,
                    registrationDate = DateTime.Now.AddDays(-30), // Simulated registration date
                    lastLogin = DateTime.Now.AddHours(-2), // Simulated last login
                    activityLevel = "Medium",
                    preferences = new
                    {
                        theme = "Light",
                        notifications = true,
                        twoFactorEnabled = false
                    }
                }
            });
        }

        // Admin-only endpoints

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllUsers()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetUserById(string id)
        {
            var user = _userService.GetById(id);
            if (user == null)
            {
                return NotFound();
            }
            return Ok(user);
        }
    }
} 