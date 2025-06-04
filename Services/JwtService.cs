using JwtRestfulApi.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtRestfulApi.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public JwtService(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        public TokenResponse GenerateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(15), // Short-lived access token (15 minutes)
                signingCredentials: credentials);

            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Generate refresh token
            var refreshToken = GenerateRefreshToken();
            
            // Add refresh token to user
            user.RefreshTokens.Add(refreshToken);
            
            // Remove old refresh tokens
            RemoveOldRefreshTokens(user);
            
            return new TokenResponse
            {
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token,
                Expiration = token.ValidTo
            };
        }
        
        public RefreshToken GenerateRefreshToken()
        {
            // Generate a secure random token
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.Now.AddDays(7), // Refresh token valid for 7 days
                Created = DateTime.Now
            };
        }
        
        public TokenResponse RefreshToken(string token, string refreshToken)
        {
            var userId = ValidateRefreshToken(refreshToken);
            if (userId == null)
            {
                throw new SecurityTokenException("Invalid refresh token");
            }
            
            var user = _userService.GetById(userId);
            if (user == null)
            {
                throw new SecurityTokenException("User not found");
            }
            
            // Get the refresh token from user
            var storedRefreshToken = user.RefreshTokens.SingleOrDefault(r => r.Token == refreshToken);
            
            if (storedRefreshToken == null || !storedRefreshToken.IsActive)
            {
                throw new SecurityTokenException("Invalid refresh token");
            }
            
            // Replace old refresh token with a new one
            var newRefreshToken = GenerateRefreshToken();
            storedRefreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);
            
            // Remove old refresh tokens
            RemoveOldRefreshTokens(user);
            
            // Generate new access token
            return new TokenResponse
            {
                Token = GenerateNewAccessToken(user),
                RefreshToken = newRefreshToken.Token,
                Expiration = DateTime.Now.AddMinutes(15)
            };
        }
        
        public string? ValidateRefreshToken(string refreshToken)
        {
            // Find user with this refresh token
            foreach (var user in _userService.GetAll())
            {
                var fullUser = _userService.GetById(user.Id);
                if (fullUser != null)
                {
                    var storedRefreshToken = fullUser.RefreshTokens.SingleOrDefault(r => r.Token == refreshToken);
                    if (storedRefreshToken != null && storedRefreshToken.IsActive)
                    {
                        return fullUser.Id;
                    }
                }
            }
            
            return null;
        }
        
        private string GenerateNewAccessToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };
            
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(15), // Short-lived access token (15 minutes)
                signingCredentials: credentials);
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
        private static void RemoveOldRefreshTokens(User user)
        {
            // Keep only non-expired, active refresh tokens or tokens that expired less than 2 days ago
            user.RefreshTokens = user.RefreshTokens
                .Where(r => r.IsActive || r.Created.AddDays(2) >= DateTime.Now)
                .ToList();
        }
    }
} 