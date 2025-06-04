using System.Text.Json.Serialization;

namespace JwtRestfulApi.Models
{
    public class User
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        [JsonIgnore] // Don't serialize password
        public string Password { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = "User"; // Default role
        
        [JsonIgnore] // Don't serialize refresh tokens
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
} 