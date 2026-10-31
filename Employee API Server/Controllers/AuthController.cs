using EmployeeApi.Model;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using EmployeeApi.DTOs.Auth;
using EmployeeApi.DataSimulation;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace EmployeeApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
        }


        [HttpPost("login")]
        [EnableRateLimiting("AuthLimiter")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // ✅ Capture caller IP once (used in all logs for tracing)
            // 📌 We store IP as a string and default to "unknown" to avoid null issues.
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ===============================
            // Step 1: Find embloyee by email
            // ===============================
            // Email is the unique login identifier in this system.
            var employee = DataSimulation.EmployeeDataSimulation.EmployeesList.FirstOrDefault(e=>e.Email == request.Email);

            // ===============================
            // Failure Path #1: Email not found
            // ===============================
            // ✅ Security logging: record the failure safely
            // ✅ We log the Email + IP only (NO password, NO tokens).
            // 📌 This helps detect brute-force / credential stuffing attempts.
            if (employee == null)
            {
                _logger.LogWarning(
                "Failed login attempt (email not found). Email={Email}, IP={IP}",
                request.Email,
                ip
                );

                return Unauthorized("Invalid credentials");
            }

            // ===============================
            // Step 2: Verify password hash
            // ===============================
            // BCrypt.Verify checks the provided password against the stored hash.
            // ✅ We never log passwords or hashes
            bool isValidPassword = BCrypt.Net.BCrypt.Verify(request.Password, employee.PasswordHash);

            // ===============================
            // Failure Path #2: Password invalid
            // ===============================
            // ✅ Security logging: record repeated password failures
            // 📌 This helps detect brute-force attempts on known emails.
            if (!isValidPassword)
            {
                _logger.LogWarning(
                "Failed login attempt (bad password). Email={Email}, IP={IP}",
                request.Email,
                ip
                );

                return Unauthorized("Invalid credentials");
            }

            // ===============================
            // Step 3: Build identity claims
            // ===============================
            // These claims are embedded in the JWT and later used for authorization.
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, employee.Id.ToString()),
                new Claim(ClaimTypes.Email, employee.Email),
                new Claim(ClaimTypes.Role, employee.Role),
            };

            // ===============================
            // Step 4: Create signing key
            // ===============================
            // 🔒 IMPORTANT: In production, move this key to configuration/secrets
            // (e.g., appsettings.json + environment secrets / KeyVault).
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("THIS_IS_A_VERY_SECRET_KEY_123456"));

            // Step 5: Token signing credentials
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            // ===============================
            // Step 6: Create the JWT access token
            // ===============================
            var token = new JwtSecurityToken(
                issuer:"EmployeeApi",
                audience:"EmployeeApiUsers",
                claims:claims,
                expires:DateTime.Now.AddMinutes(30),
                signingCredentials: creds
                );

            // Step 7: Serialize JWT to string
            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Step 8: Create refresh token
            var refreshToken = GenerateRefreshToken();

            // Step 9: Store refresh token securely
            // ✅ Store HASH only (never store raw refresh token in server storage).
            employee.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(refreshToken);
            employee.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            employee.RefreshTokenRevokedAt = null;

            // Step 10: Optional success log (low noise)
            // ===============================
            // ✅ Safe success log: user ID + email + IP only (NO tokens)
            // 📌 Useful for later investigations (timeline reconstruction).
            _logger.LogInformation("Successful login. UserId={UserId}, Email={Email}, IP={IP}", employee.Id, employee.Email, ip);

            // Return tokens to client:
            // - AccessToken: used for API calls
            // - RefreshToken: used to renew access token later
            return Ok(new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }


        [HttpPost("refresh")]
        [EnableRateLimiting("AuthLimiter")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            // ✅ Capture caller IP once (used in all logs for tracing)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ===============================
            // Step 1: Find embloyee by email
            // ===============================
            var embloyee = EmployeeDataSimulation.EmployeesList
                .FirstOrDefault(s => s.Email == request.Email);

            // ===============================
            // Failure Path #1: Email not found
            // ===============================
            // ✅ Safe log: Email + IP only
            // 📌 Helps detect refresh probing / abuse attempts.
            if (embloyee == null)
            {
                _logger.LogWarning(
                    "Invalid refresh attempt (email not found). Email={Email}, IP={IP}",
                    request.Email,
                    ip
                );

                return Unauthorized("Invalid refresh request");
            }

            // ===============================
            // Failure Path #2: Token already revoked
            // ===============================
            // ✅ Safe log: UserId + Email + IP only
            // 📌 Indicates possible reuse of an old token (suspicious).
            if (embloyee.RefreshTokenRevokedAt != null)
            {
                _logger.LogWarning(
                    "Refresh attempt using revoked token. UserId={UserId}, Email={Email}, IP={IP}",
                    embloyee.Id,
                    embloyee.Email,
                    ip
                );

                return Unauthorized("Refresh token is revoked");
            }

            // ===============================
            // Failure Path #3: Token expired
            // ===============================
            // ✅ Safe log: UserId + Email + IP only
            // 📌 Expired refresh usage can be normal or automated retry — log helps visibility.
            if (embloyee.RefreshTokenExpiresAt == null || embloyee.RefreshTokenExpiresAt <= DateTime.UtcNow)
            {
                _logger.LogWarning(
                    "Refresh attempt using expired token. UserId={UserId}, Email={Email}, IP={IP}",
                    embloyee.Id,
                    embloyee.Email,
                    ip
                );

                return Unauthorized("Refresh token expired");
            }

            // ===============================
            // Failure Path #4: Invalid refresh token value
            // ===============================
            // ❌ Never log the raw refresh token
            // ✅ Only log outcome + identity data
            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, embloyee.RefreshTokenHash);
            if (!refreshValid)
            {
                _logger.LogWarning(
                    "Invalid refresh token attempt. UserId={UserId}, Email={Email}, IP={IP}",
                    embloyee.Id,
                    embloyee.Email,
                    ip
                );

                return Unauthorized("Invalid refresh token");
            }

            // ===============================
            // Success: Issue NEW access token (same claims & signing settings as login)
            // ===============================
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, embloyee.Id.ToString()),
                new Claim(ClaimTypes.Email, embloyee.Email),
                new Claim(ClaimTypes.Role, embloyee.Role)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("THIS_IS_A_VERY_SECRET_KEY_123456"));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var jwt = new JwtSecurityToken(
                issuer: "EmployeeApi",
                audience: "EmployeeApiUsers",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            var newAccessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

            // ===============================
            // Rotation: Replace refresh token
            // ===============================
            // ✅ Token rotation reduces damage if a refresh token is stolen.
            var newRefreshToken = GenerateRefreshToken();
            embloyee.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(newRefreshToken);
            embloyee.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            embloyee.RefreshTokenRevokedAt = null;

            // ✅ Optional low-noise success log (safe)
            _logger.LogInformation(
                "Refresh succeeded. UserId={UserId}, Email={Email}, IP={IP}",
                embloyee.Id,
                embloyee.Email,
                ip
            );

            return Ok(new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("logout")]
        public IActionResult Logout([FromBody] LogoutRequest request)
        {
            var employee = EmployeeDataSimulation.EmployeesList
                .FirstOrDefault(s => s.Email == request.Email);

            if (employee == null)
                return Ok(); // Do not reveal if user exists

            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, employee.RefreshTokenHash);
            if (!refreshValid)
                return Ok();

            employee.RefreshTokenRevokedAt = DateTime.UtcNow;
            return Ok("Logged out successfully");
        }

        private static string GenerateRefreshToken()
        {
            var bytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
