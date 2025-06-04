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