# Hướng dẫn xây dựng RESTful API với JWT Authentication sử dụng ASP.NET Core 9

Tài liệu này hướng dẫn chi tiết cách xây dựng một RESTful API với xác thực JWT (JSON Web Token) sử dụng ASP.NET Core 9.

## Các tính năng

- Xác thực dựa trên JWT token
- Cơ chế refresh token
- Đăng ký và đăng nhập người dùng
- Phân quyền theo vai trò (role-based authorization)
- API endpoints dành riêng cho Admin và User
- Bảo vệ API endpoints
- Tài liệu Swagger/OpenAPI
- Hỗ trợ token không cần tiền tố "Bearer"

## Yêu cầu

- .NET 9 SDK
- Visual Studio 2022 hoặc bất kỳ trình soạn thảo mã nào (VS Code, v.v.)

## Hướng dẫn chi tiết xây dựng từng bước

### 1. Tạo dự án ASP.NET Core Web API

```bash
# Tạo dự án mới
dotnet new webapi -n JwtRestfulApi

# Di chuyển vào thư mục dự án
cd JwtRestfulApi
```

### 2. Cài đặt các package cần thiết

```bash
# Package để xác thực JWT
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

# Package để tài liệu API với Swagger
dotnet add package Swashbuckle.AspNetCore
```

### 3. Tạo cấu trúc thư mục

```bash
# Tạo các thư mục cần thiết
mkdir Models
mkdir Services
mkdir Controllers
```

### 4. Xây dựng các model

#### 4.1 User Model (Models/User.cs)

```csharp
using System.Text.Json.Serialization;

namespace JwtRestfulApi.Models
{
    public class User
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        [JsonIgnore] // Không serialize mật khẩu
        public string Password { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = "User"; // Vai trò mặc định
        
        [JsonIgnore] // Không serialize refresh tokens
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
```

#### 4.2 LoginModel (Models/LoginModel.cs)

```csharp
using System.ComponentModel.DataAnnotations;

namespace JwtRestfulApi.Models
{
    public class LoginModel
    {
        [Required]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
```

#### 4.3 RegisterModel (Models/RegisterModel.cs)

```csharp
using System.ComponentModel.DataAnnotations;

namespace JwtRestfulApi.Models
{
    public class RegisterModel
    {
        [Required]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;
        
        [Required]
        [Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
```

#### 4.4 TokenResponse (Models/TokenResponse.cs)

```csharp
namespace JwtRestfulApi.Models
{
    public class TokenResponse
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
    }
}
```

#### 4.5 RefreshToken (Models/RefreshToken.cs)

```csharp
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
```

### 5. Cài đặt các service

#### 5.1 Interface JWT Service (Services/IJwtService.cs)

```csharp
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
```

#### 5.2 Triển khai JWT Service (Services/JwtService.cs)

```csharp
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
                expires: DateTime.Now.AddMinutes(15), // Access token có hiệu lực 15 phút
                signingCredentials: credentials);

            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Tạo refresh token
            var refreshToken = GenerateRefreshToken();
            
            // Thêm refresh token vào user
            user.RefreshTokens.Add(refreshToken);
            
            // Xóa các refresh token cũ
            RemoveOldRefreshTokens(user);
            
            return new TokenResponse
            {
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token,
                Expiration = token.ValidTo
            };
        }
        
        // Các phương thức khác được triển khai...
        
        public RefreshToken GenerateRefreshToken()
        {
            // Tạo token ngẫu nhiên an toàn
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.Now.AddDays(7), // Refresh token có hiệu lực 7 ngày
                Created = DateTime.Now
            };
        }
        
        private static void RemoveOldRefreshTokens(User user)
        {
            // Giữ lại các refresh token còn hiệu lực hoặc hết hiệu lực chưa đến 2 ngày
            user.RefreshTokens = user.RefreshTokens
                .Where(r => r.IsActive || r.Created.AddDays(2) >= DateTime.Now)
                .ToList();
        }
        
        // Các phương thức khác...
    }
}
```

#### 5.3 Interface User Service (Services/IUserService.cs)

```csharp
using JwtRestfulApi.Models;

namespace JwtRestfulApi.Services
{
    public interface IUserService
    {
        User? Authenticate(string username, string password);
        User? GetById(string id);
        User Register(RegisterModel model);
        IEnumerable<User> GetAll();
    }
}
```

#### 5.4 Triển khai User Service (Services/UserService.cs)

```csharp
using JwtRestfulApi.Models;
using System.Security.Cryptography;
using System.Text;

namespace JwtRestfulApi.Services
{
    public class UserService : IUserService
    {
        // Trong ứng dụng thật, đây sẽ là cơ sở dữ liệu
        private List<User> _users = new List<User>
        {
            new User { Id = "1", Username = "admin", Password = HashPassword("admin"), Email = "admin@example.com", Role = "Admin" },
            new User { Id = "2", Username = "user", Password = HashPassword("user"), Email = "user@example.com", Role = "User" }
        };

        public User? Authenticate(string username, string password)
        {
            var hashedPassword = HashPassword(password);
            return _users.SingleOrDefault(x => x.Username == username && x.Password == hashedPassword);
        }

        public User? GetById(string id)
        {
            return _users.FirstOrDefault(x => x.Id == id);
        }

        public User Register(RegisterModel model)
        {
            // Kiểm tra xem người dùng đã tồn tại chưa
            if (_users.Any(x => x.Username == model.Username))
            {
                throw new Exception("Username đã tồn tại");
            }

            // Tạo người dùng mới
            var user = new User
            {
                Id = (_users.Count + 1).ToString(),
                Username = model.Username,
                Password = HashPassword(model.Password),
                Email = model.Email
            };

            _users.Add(user);
            return user;
        }

        public IEnumerable<User> GetAll()
        {
            // Trả về người dùng mà không có mật khẩu
            return _users.Select(u => new User
            {
                Id = u.Id,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role
            });
        }

        private static string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
```

### 6. Xây dựng các controller

#### 6.1 Auth Controller (Controllers/AuthController.cs)

```csharp
using JwtRestfulApi.Models;
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtService _jwtService;

        public AuthController(IUserService userService, IJwtService jwtService)
        {
            _userService = userService;
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            var user = _userService.Authenticate(model.Username, model.Password);
            
            if (user == null)
            {
                return Unauthorized(new { message = "Tên đăng nhập hoặc mật khẩu không chính xác" });
            }

            var tokenResponse = _jwtService.GenerateToken(user);
            return Ok(tokenResponse);
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterModel model)
        {
            try
            {
                var user = _userService.Register(model);
                return Ok(new { message = "Đăng ký thành công" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
        
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var tokenResponse = _jwtService.RefreshToken(request.Token, request.RefreshToken);
                return Ok(tokenResponse);
            }
            catch (SecurityTokenException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
    
    public class RefreshTokenRequest
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }
}
```

#### 6.2 Users Controller (Controllers/UsersController.cs)

```csharp
using JwtRestfulApi.Models;
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Đảm bảo tất cả các endpoints đều yêu cầu xác thực
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        // Endpoints công khai cho tất cả người dùng đã xác thực

        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            // Lấy ID người dùng hiện tại từ claims
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized(new { message = "Người dùng chưa được xác thực" });
            }

            var user = _userService.GetById(userId);
            if (user == null)
            {
                return NotFound(new { message = "Không tìm thấy người dùng" });
            }

            // Trả về thông tin người dùng không có dữ liệu nhạy cảm
            return Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Role
            });
        }

        // Endpoint này chỉ có sẵn cho người dùng cụ thể hoặc admin
        [HttpGet("personal-data/{id}")]
        public IActionResult GetPersonalData(string id)
        {
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;

            // Kiểm tra xem người dùng có đang yêu cầu dữ liệu của chính họ hoặc là admin
            if (currentUserId != id && userRole != "Admin")
            {
                return Forbid();
            }

            var user = _userService.GetById(id);
            if (user == null)
            {
                return NotFound(new { message = "Không tìm thấy người dùng" });
            }

            // Mô phỏng truy xuất dữ liệu cá nhân
            return Ok(new
            {
                userId = user.Id,
                personalData = new
                {
                    username = user.Username,
                    email = user.Email,
                    registrationDate = DateTime.Now.AddDays(-30), // Ngày đăng ký mô phỏng
                    lastLogin = DateTime.Now.AddHours(-2) // Lần đăng nhập cuối cùng mô phỏng
                }
            });
        }

        // Endpoints chỉ dành cho admin

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
```

#### 6.3 Admin Controller (Controllers/AdminController.cs)

```csharp
using JwtRestfulApi.Models;
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace JwtRestfulApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")] // Giới hạn toàn bộ controller chỉ cho vai trò admin
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
            // Mô phỏng thống kê hệ thống
            return Ok(new
            {
                title = "Admin Dashboard",
                stats = new
                {
                    totalUsers = 54, // Dữ liệu mô phỏng
                    activeUsers = 32,
                    newUsersToday = 3,
                    systemUptime = "99.98%",
                    avgResponseTime = "120ms"
                }
            });
        }

        [HttpGet("system-health")]
        public IActionResult GetSystemHealth()
        {
            // Mô phỏng trạng thái sức khỏe hệ thống
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
    }
}
```

### 7. Cấu hình JWT trong appsettings.json

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Key": "YourSecretKeyForAuthenticationOfApplication",
    "Issuer": "https://localhost:7218",
    "Audience": "https://localhost:7218"
  }
}
```

### 8. Cấu hình Startup trong Program.cs

```csharp
using JwtRestfulApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Thêm các dịch vụ vào container
builder.Services.AddControllers();

// Cấu hình Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT Restful API", Version = "v1" });
    
    // Thêm xác thực JWT vào Swagger
    c.AddSecurityDefinition("JWT", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header. Nhập token của bạn trực tiếp mà không cần tiền tố 'Bearer'.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "JWT"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Đăng ký dịch vụ - tránh phụ thuộc vòng
builder.Services.AddSingleton<IUserService, UserService>();
// Sử dụng factory để giải quyết UserService khi tạo JwtService
builder.Services.AddSingleton<IJwtService>(provider => 
    new JwtService(
        provider.GetRequiredService<IConfiguration>(), 
        provider.GetRequiredService<IUserService>()));

// Cấu hình xác thực JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            // Cho phép chênh lệch thời gian 5 phút
            ClockSkew = TimeSpan.FromMinutes(5)
        };
        
        // Trích xuất token tùy chỉnh để xử lý cả có và không có tiền tố "Bearer"
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (authHeader != null)
                {
                    // Kiểm tra xem token có bắt đầu bằng "Bearer " không
                    if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        // Định dạng chuẩn - không làm gì, framework sẽ xử lý nó
                        return Task.CompletedTask;
                    }
                    else
                    {
                        // Không có tiền tố "Bearer" - thêm nó theo chương trình
                        context.Token = authHeader;
                    }
                }
                return Task.CompletedTask;
            }
        };
    });

var app = builder.Build();

// Cấu hình HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Thêm middleware xác thực
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
```

## API Endpoints

### Xác thực

- **POST /api/auth/register** - Đăng ký người dùng mới
  - Request body: `{ "username": "string", "email": "string", "password": "string", "confirmPassword": "string" }`

- **POST /api/auth/login** - Đăng nhập và nhận JWT token
  - Request body: `{ "username": "string", "password": "string" }`
  - Response: `{ "token": "string", "refreshToken": "string", "expiration": "datetime" }`

- **POST /api/auth/refresh-token** - Làm mới JWT token đã hết hạn
  - Request body: `{ "token": "string", "refreshToken": "string" }`
  - Response: `{ "token": "string", "refreshToken": "string", "expiration": "datetime" }`

### Endpoints cho người dùng (yêu cầu xác thực)

- **GET /api/users/profile** - Lấy thông tin hồ sơ người dùng hiện tại (có sẵn cho tất cả người dùng đã xác thực)
- **GET /api/users/basic-info** - Lấy thông tin cơ bản của người dùng (có sẵn cho tất cả người dùng đã xác thực)
- **GET /api/users/personal-data/{id}** - Lấy dữ liệu cá nhân (chỉ có sẵn cho chính người dùng đó hoặc admin)

### Endpoints cho admin (yêu cầu vai trò Admin)

- **GET /api/users** - Lấy danh sách tất cả người dùng
- **GET /api/users/{id}** - Lấy thông tin người dùng theo ID
- **GET /api/admin/dashboard** - Lấy thống kê dashboard admin
- **GET /api/admin/system-health** - Lấy thông tin sức khỏe hệ thống
- **GET /api/admin/user-management** - Lấy dữ liệu quản lý người dùng
- **POST /api/admin/simulate-action** - Mô phỏng hành động của admin

### Endpoints tài nguyên (truy cập dựa trên vai trò)

- **GET /api/resource/public-resources** - Có sẵn cho tất cả người dùng đã xác thực
- **GET /api/resource/user-resources** - Có sẵn cho người dùng có vai trò "User" hoặc "Admin"
- **GET /api/resource/admin-resources** - Chỉ có sẵn cho người dùng có vai trò "Admin"
- **GET /api/resource/mixed-resources** - Trả về các tài nguyên khác nhau dựa trên vai trò của người dùng

## Phân quyền dựa trên vai trò

API triển khai phân quyền dựa trên vai trò với hai vai trò chính:

### Vai trò User
- Có thể truy cập thông tin hồ sơ của riêng mình
- Có thể xem các tài nguyên cơ bản
- Không thể truy cập các endpoint dành cho admin hoặc dữ liệu của người dùng khác

### Vai trò Admin
- Có thể truy cập tất cả các endpoint của người dùng
- Có thể truy cập các endpoint dành riêng cho admin
- Có thể xem tất cả dữ liệu người dùng
- Có quyền truy cập vào các tính năng quản lý hệ thống

## Người dùng mặc định

Để thuận tiện cho việc kiểm thử, ứng dụng đi kèm với hai người dùng được cấu hình sẵn:

- Người dùng Admin:
  - Tên đăng nhập: admin
  - Mật khẩu: admin
  - Vai trò: Admin

- Người dùng thông thường:
  - Tên đăng nhập: user
  - Mật khẩu: user
  - Vai trò: User

## Các bước sử dụng API

1. Đăng ký người dùng mới bằng endpoint `/api/auth/register`
2. Đăng nhập bằng endpoint `/api/auth/login` để nhận JWT token và refresh token
3. Sử dụng token trong header Authorization cho các endpoint được bảo vệ:
   - Bạn có thể sử dụng một trong hai cách sau:
     - `Authorization: Bearer {your_token}` (định dạng chuẩn)
     - `Authorization: {your_token}` (định dạng đơn giản không có tiền tố Bearer)
4. Khi access token hết hạn, sử dụng endpoint `/api/auth/refresh-token` để lấy cặp token mới
5. Truy cập các endpoint khác nhau dựa trên vai trò của bạn:
   - Người dùng thông thường chỉ có thể truy cập các endpoint dành cho người dùng
   - Người dùng admin có thể truy cập cả endpoint người dùng và admin

## Lưu ý bảo mật

- Sử dụng HTTPS trong môi trường sản xuất
- Lưu trữ dữ liệu nhạy cảm (như JWT key) bằng cách sử dụng quản lý bí mật
- Triển khai băm mật khẩu đúng cách (bản demo này sử dụng SHA256, nhưng trong sản xuất, nên sử dụng thuật toán an toàn hơn như BCrypt)
- Access token có thời gian ngắn giúp cải thiện bảo mật (15 phút trong triển khai này)
- Refresh token được lưu trữ với bản ghi người dùng và có thể thu hồi nếu cần
- Refresh token cũ được tự động dọn dẹp

## Giấy phép

MIT 