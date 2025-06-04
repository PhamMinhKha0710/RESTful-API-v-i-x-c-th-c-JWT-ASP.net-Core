namespace JwtRestfulApi.Models
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires { get; set; }
        public bool IsExpired => DateTime.Now >= Expires;
        public string? ReplacedByToken { get; set; }
        public bool IsActive => !IsExpired && ReplacedByToken == null;
    }
} 