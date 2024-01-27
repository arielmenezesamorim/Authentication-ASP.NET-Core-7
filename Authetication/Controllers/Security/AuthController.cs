using Domain.Interfaces.IServices.Security;
using Entities.Models.Security.Token;
using Entities.Models.Security.Usuario;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AutheticationAPI.Controllers.Security
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthController(IAuthService authService,
                              ILogger<AuthController> logger,
                              IConfiguration configuration,
                              UserManager<ApplicationUser> userManager)
        {
            _authService = authService;
            _logger = logger;
            _configuration = configuration;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");
                var response = await _authService.Register(register);
                if (response.Status >= 400)
                {
                    return BadRequest(response);
                }
                return Ok(response);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(Login login)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");
                var response = await _authService.Login(login);
                if (response.Status >= 401)
                    return BadRequest(response);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenData refreshTokenData)
        {
            try
            {
                if (refreshTokenData is null)
                {
                    return BadRequest("Invalid client request");
                }

                var response = await _authService.GetRefreshToken(refreshTokenData);
                if (response.Status >= 400)
                    return BadRequest(response);

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}
