namespace Login.DTOs
{
    public class ForgotPasswordDTO
    {
        public string Email { get; set; } = null!;
    }

    public class ResetPasswordDTO
    {
        public string Token { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
    }
}
