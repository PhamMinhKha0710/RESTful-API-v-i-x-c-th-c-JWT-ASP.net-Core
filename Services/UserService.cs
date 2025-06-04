using JwtRestfulApi.Models;
using System.Security.Cryptography;
using System.Text;

namespace JwtRestfulApi.Services
{
    public class UserService : IUserService
    {
        // In a real application, this would be a database
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
            // Check if user already exists
            if (_users.Any(x => x.Username == model.Username))
            {
                throw new Exception("Username already exists");
            }

            // Create new user
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
            // Return users without passwords
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