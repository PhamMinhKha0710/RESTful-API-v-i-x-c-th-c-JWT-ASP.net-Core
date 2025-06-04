using JwtRestfulApi.Models;

namespace JwtRestfulApi.Services
{
    public interface IJwtService
    {
        TokenResponse GenerateToken(User user);
        RefreshToken GenerateRefreshToken();
        TokenResponse RefreshToken(string token, string refreshToken);
        string? ValidateRefreshToken(string token);
    }
} 