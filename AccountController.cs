using Login.Data;
using Login.DTOs;
using Login.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Login.Services;
using System.Text.RegularExpressions;

namespace Login.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;

        public AuthController(AppDbContext context)
        {
            _context = context;
        }

        //  Register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO dto)
        {
            if (dto.Password != dto.ConfirmPassword)
                return BadRequest("Passwords do not match.");

            if (!IsValidEmail(dto.Email))
                return BadRequest("Invalid email format.");

            if (!IsStrongPassword(dto.Password))
                return BadRequest("Password must be at least 8 characters long with letters, numbers, and special chars.");

            bool emailExists = await _context.Users.AnyAsync(u => u.Email == dto.Email);
            if (emailExists)
                return BadRequest("Email already registered.");

            var user = new User
            {
                Name = dto.Name,
                Phone = dto.Phone,
                Email = dto.Email,
                PasswordHash = PasswordHasher.HashPassword(dto.Password)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("Registration successful. Please login.");
        }

        // Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
                return BadRequest("Email and Password are required.");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                return Unauthorized("Invalid Credentials.");

            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            {
                var remaining = (user.LockoutEnd.Value - DateTime.UtcNow).Minutes;
                return Unauthorized($"Account locked. Try again in {remaining} mins.");
            }

            if (!PasswordHasher.VerifyPassword(dto.Password, user.PasswordHash))
            {
                user.FailedLoginAttempts++;
                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(30);
                    await _context.SaveChangesAsync();
                    return Unauthorized("Too many failed attempts. Account locked for 30 mins.");
                }
                await _context.SaveChangesAsync();
                return Unauthorized("Invalid Credentials.");
            }

            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _context.SaveChangesAsync();

            return Ok("Login successful! Welcome.");
        }

        //  Forgot Password
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email))
                return BadRequest("Email is required.");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                return Ok("If your email exists, you’ll get reset instructions.");

            var token = Guid.NewGuid().ToString();
            var resetToken = new PasswordResetToken
            {
                Token = token,
                UserId = user.Id,
                ExpiryTime = DateTime.UtcNow.AddHours(1)
            };

            _context.PasswordResetTokens.Add(resetToken);
            await _context.SaveChangesAsync();

            string resetLink = $"https://yourfrontend.com/reset-password?token={token}";

            return Ok($"If your email exists, you’ll get reset instructions. (Test link: {resetLink})");
        }

        //  Reset Password
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO dto)
        {
            if (dto.NewPassword != dto.ConfirmPassword)
                return BadRequest("Passwords do not match.");

            if (!IsStrongPassword(dto.NewPassword))
                return BadRequest("Password must be strong.");

            var tokenEntry = await _context.PasswordResetTokens.Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Token == dto.Token);

            if (tokenEntry == null || tokenEntry.ExpiryTime < DateTime.UtcNow)
                return NotFound("Invalid or expired token.");

            tokenEntry.User.PasswordHash = PasswordHasher.HashPassword(dto.NewPassword);
            _context.PasswordResetTokens.Remove(tokenEntry);

            await _context.SaveChangesAsync();

            return Ok("Password changed successfully. Please login with your new password.");
        }

        //  Google OAuth
        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties { RedirectUri = Url.Action("GoogleResponse") };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
                return Unauthorized("Google Authentication failed.");

            var claims = result.Principal.Identities.FirstOrDefault()?.Claims;
            var email = claims?.FirstOrDefault(c => c.Type.Contains("emailaddress"))?.Value;
            var name = claims?.FirstOrDefault(c => c.Type.Contains("name"))?.Value;

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                user = new User
                {
                    Name = name ?? "Google User",
                    Email = email!,
                    Phone = "",
                    PasswordHash = ""
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
            }

            return Ok($"Welcome {name}! Google login successful.");
        }

        // LinkedIn OAuth
        [HttpGet("linkedin-login")]
        public IActionResult LinkedInLogin()
        {
            var properties = new AuthenticationProperties { RedirectUri = Url.Action("LinkedInResponse") };
            return Challenge(properties, "LinkedIn");
        }

        [HttpGet("linkedin-response")]
        public async Task<IActionResult> LinkedInResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
                return Unauthorized("LinkedIn Authentication failed.");

            var claims = result.Principal.Identities.FirstOrDefault()?.Claims;
            var email = claims?.FirstOrDefault(c => c.Type == "email")?.Value;
            var firstName = claims?.FirstOrDefault(c => c.Type == "urn:linkedin:firstName")?.Value;
            var lastName = claims?.FirstOrDefault(c => c.Type == "urn:linkedin:lastName")?.Value;
            var fullName = $"{firstName} {lastName}";

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                user = new User
                {
                    Name = fullName,
                    Email = email ?? "LinkedInUser",
                    Phone = "",
                    PasswordHash = ""
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
            }

            return Ok($"Welcome {fullName}! LinkedIn login successful.");
        }

        // Facebook OAuth
        [HttpGet("facebook-login")]
        public IActionResult FacebookLogin()
        {
            var properties = new AuthenticationProperties { RedirectUri = Url.Action("FacebookResponse") };
            return Challenge(properties, "Facebook");
        }

        [HttpGet("facebook-response")]
        public async Task<IActionResult> FacebookResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
                return Unauthorized("Facebook Authentication failed.");

            var claims = result.Principal.Identities.FirstOrDefault()?.Claims;
            var email = claims?.FirstOrDefault(c => c.Type.Contains("email"))?.Value;
            var name = claims?.FirstOrDefault(c => c.Type.Contains("name"))?.Value;

            if (email == null)
                return BadRequest("Facebook did not return an email. Please ensure your FB account has a verified email.");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                user = new User
                {
                    Name = name ?? "Facebook User",
                    Email = email,
                    Phone = "",
                    PasswordHash = ""
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
            }

            return Ok($"Welcome {name}! Facebook login successful.");
        }

        
        private static bool IsValidEmail(string email) =>
            Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

        private static bool IsStrongPassword(string password) =>
            Regex.IsMatch(password, @"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$");

    }
}
