using Domain.Interfaces.IServices.Security;
using Entities.Constant;
using Entities.Models.Security.Token;
using Entities.Models.Security.Usuario;
using Entities.Notification;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Services.Security
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(
                            UserManager<ApplicationUser> userManager,
                            RoleManager<IdentityRole> roleManager,
                            IConfiguration configuration
                          )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;

        }

        public async Task<Response> Register(Register register)
        {
            var userExists = await _userManager.FindByEmailAsync(register.Email);
            if (userExists != null)
                return CustomResponse(StatusCode.Unauthorized, "Já existe um usuário cadastrado com esse e-mail.", register.Email);

            ApplicationUser user = new()
            {
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.Username,
                FirstName = register.FirstName,
                LastName = register.LastName,
            };

            var createUserResult = await _userManager.CreateAsync(user, register.Password);
            if (!createUserResult.Succeeded)
                return CustomResponse(StatusCode.Unauthorized, "Falha na criação do usuário! Verifique os detalhes do usuário e tente novamente.", createUserResult);

            if (!await _roleManager.RoleExistsAsync(register.Role))
                await _roleManager.CreateAsync(new IdentityRole(register.Role));

            if (await _roleManager.RoleExistsAsync(register.Role))
                await _userManager.AddToRoleAsync(user, register.Role);

            return CustomResponse(StatusCode.Created, "Usuário cadastrado com sucesso!", createUserResult);
        }

        public async Task<Response> Login(Login login)
        {
            TokenData _tokenData = new();
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user == null)
            {
                return CustomResponse(StatusCode.Unauthorized, "E-mail inválido", login.Email);
            }
            if (!await _userManager.CheckPasswordAsync(user, login.Password))
            {
                return CustomResponse(StatusCode.Unauthorized, "Senha inválida", login.Password);
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
               new Claim(ClaimTypes.Email, user.Email),
               new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
               new Claim(ClaimTypes.Name, user.Email),
               new Claim("NameComplete", user.LastName + " " + user.FirstName),
               new Claim(JwtRegisteredClaimNames.UniqueName, user.Id.ToString()),
               new Claim(JwtRegisteredClaimNames.Email, user.Email),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            _tokenData.AccessToken = GenerateToken(authClaims);
            _tokenData.RefreshToken = GenerateRefreshToken();

            var _RefreshTokenValidityInDays = Convert.ToInt64(_configuration["JWT:RefreshTokenValidityInDays"]);
            user.RefreshToken = _tokenData.RefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_RefreshTokenValidityInDays);
            await _userManager.UpdateAsync(user);

            return CustomResponse(StatusCode.Ok, "Token gerado com sucesso!", _tokenData);
        }

        public async Task<Response> GetRefreshToken(RefreshTokenData refreshTokenData)
        {
            TokenData _tokenData = new();
            var principal = GetPrincipalFromExpiredToken(refreshTokenData.AccessToken);
            string email = principal.Identity.Name;
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null || user.RefreshToken != refreshTokenData.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return CustomResponse(StatusCode.BadRequest, "Access Token ou Refresh Token inválido", refreshTokenData);
            }

            var authClaims = new List<Claim>
            {
               new Claim(ClaimTypes.Email, user.Email),
               new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
               new Claim(ClaimTypes.Name, user.Email),
               new Claim("NameComplete", user.LastName + " " + user.FirstName),
               new Claim(JwtRegisteredClaimNames.UniqueName, user.Id.ToString()),
               new Claim(JwtRegisteredClaimNames.Email, user.Email),
            };
            var newAccessToken = GenerateToken(authClaims);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            _tokenData.AccessToken = newAccessToken;
            _tokenData.RefreshToken = newRefreshToken;
            return CustomResponse(StatusCode.Created, "Refresh Token gerado com sucesso.", _tokenData);
        }

        private string GenerateToken(IEnumerable<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var _TokenExpiryTimeInHour = Convert.ToInt64(_configuration["JWT:TokenExpiryTimeInHour"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _configuration["JWT:ValidIssuer"],
                Audience = _configuration["JWT:ValidAudience"],
                Expires = DateTime.UtcNow.AddHours(_TokenExpiryTimeInHour),
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(claims)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Token inválido");

            return principal;
        }

        private Response CustomResponse(int statusCode, string message, object value)
        {
            var response = new Response()
            { Status = statusCode, Message = message, Object = value };

            return response;
        }
    }
}
