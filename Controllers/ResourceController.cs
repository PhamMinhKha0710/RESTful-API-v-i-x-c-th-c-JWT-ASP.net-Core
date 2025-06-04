using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Require authentication for all endpoints
    public class ResourceController : ControllerBase
    {
        // Public resources accessible to all authenticated users
        [HttpGet("public-resources")]
        public IActionResult GetPublicResources()
        {
            return Ok(new
            {
                message = "These resources are available to all authenticated users",
                resources = new[]
                {
                    new { id = 1, name = "Basic Guide", type = "PDF", size = "1.2 MB" },
                    new { id = 2, name = "User Manual", type = "PDF", size = "2.4 MB" },
                    new { id = 3, name = "FAQ", type = "HTML", size = "0.5 MB" }
                }
            });
        }
        
        // Role-specific endpoints
        
        // User-level resources
        [HttpGet("user-resources")]
        [Authorize(Roles = "User,Admin")] // Both User and Admin roles can access
        public IActionResult GetUserResources()
        {
            var username = User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
            
            return Ok(new
            {
                message = $"Hello {username}, these resources are available to users",
                resources = new[]
                {
                    new { id = 101, name = "Personal Dashboard", type = "Web App", description = "Track your personal activity" },
                    new { id = 102, name = "Profile Settings", type = "Settings", description = "Manage your profile settings" },
                    new { id = 103, name = "Notification Preferences", type = "Settings", description = "Manage your notifications" }
                }
            });
        }
        
        // Admin-level resources
        [HttpGet("admin-resources")]
        [Authorize(Roles = "Admin")] // Only Admin role can access
        public IActionResult GetAdminResources()
        {
            return Ok(new
            {
                message = "These resources are only available to administrators",
                resources = new[]
                {
                    new { id = 501, name = "System Configuration", type = "Admin Tool", access = "Full" },
                    new { id = 502, name = "User Management", type = "Admin Tool", access = "Full" },
                    new { id = 503, name = "Audit Logs", type = "Report", access = "Full" },
                    new { id = 504, name = "Security Settings", type = "Admin Tool", access = "Full" }
                }
            });
        }
        
        // Demonstrates policy-based access restriction
        [HttpGet("mixed-resources")]
        public IActionResult GetMixedResources()
        {
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;
            var username = User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
            
            var baseResources = new List<object>
            {
                new { id = 201, name = "Common Resource 1", type = "Data", accessLevel = "All Users" },
                new { id = 202, name = "Common Resource 2", type = "Data", accessLevel = "All Users" }
            };
            
            // Add role-specific resources
            if (userRole == "Admin")
            {
                baseResources.Add(new { id = 301, name = "Admin Resource 1", type = "Sensitive Data", accessLevel = "Admin Only" });
                baseResources.Add(new { id = 302, name = "Admin Resource 2", type = "Sensitive Data", accessLevel = "Admin Only" });
            }
            
            return Ok(new
            {
                username,
                role = userRole,
                message = "Resources are filtered based on your role",
                accessGranted = DateTime.Now,
                resources = baseResources
            });
        }
    }
} 