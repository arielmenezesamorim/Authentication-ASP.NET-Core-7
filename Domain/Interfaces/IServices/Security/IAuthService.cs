using Entities.Models.Security.Token;
using Entities.Models.Security.Usuario;
using Entities.Notification;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Interfaces.IServices.Security
{
    public interface IAuthService
    {
        Task<Response> Register(Register register);
        Task<Response> Login(Login login);
        Task<Response> GetRefreshToken(RefreshTokenData refreshTokenData);
    }
}
