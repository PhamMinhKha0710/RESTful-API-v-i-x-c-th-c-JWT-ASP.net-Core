using JwtRestfulApi.Models;
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")] // Restrict the entire controller to admin role
    public class AdminController : ControllerBase
    {
        private readonly IUserService _userService;

        public AdminController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("dashboard")]
        public IActionResult GetDashboard()
        {
            // Simulate system statistics
            return Ok(new
            {
                title = "Admin Dashboard",
                stats = new
                {
                    totalUsers = 54, // Simulated data
                    activeUsers = 32,
                    newUsersToday = 3,
                    systemUptime = "99.98%",
                    avgResponseTime = "120ms"
                },
                alerts = new List<object>
                {
                    new { level = "info", message = "System update scheduled for next week" },
                    new { level = "warning", message = "High CPU usage detected" },
                    new { level = "error", message = "Payment gateway timeout at 14:30" }
                }
            });
        }

        [HttpGet("system-health")]
        public IActionResult GetSystemHealth()
        {
            // Simulate system health status
            return Ok(new
            {
                status = "Healthy",
                components = new List<object>
                {
                    new { name = "Database", status = "Online", responseTime = "45ms" },
                    new { name = "Authentication Service", status = "Online", responseTime = "30ms" },
                    new { name = "Storage Service", status = "Online", responseTime = "65ms" },
                    new { name = "Email Service", status = "Degraded", responseTime = "210ms" }
                },
                lastChecked = DateTime.Now
            });
        }

        [HttpGet("user-management")]
        public IActionResult GetUserManagement()
        {
            var users = _userService.GetAll();
            
            return Ok(new
            {
                userCount = users.Count(),
                users = users,
                actions = new[] { "Create", "Edit", "Delete", "Reset Password", "Change Role" }
            });
        }

        [HttpPost("simulate-action")]
        public IActionResult SimulateAdminAction([FromBody] AdminAction action)
        {
            // Log the admin action (in a real app)
            // Perform the action (in a real app)
            
            return Ok(new
            {
                success = true,
                message = $"Admin action '{action.ActionType}' on {action.TargetType} '{action.TargetId}' simulated successfully",
                timestamp = DateTime.Now
            });
        }
    }

    public class AdminAction
    {
        public string ActionType { get; set; } = string.Empty; // e.g., "delete", "suspend", "promote"
        public string TargetType { get; set; } = string.Empty; // e.g., "user", "content", "role"
        public string TargetId { get; set; } = string.Empty;   // ID of the target entity
        public Dictionary<string, string>? AdditionalData { get; set; }
    }
} 