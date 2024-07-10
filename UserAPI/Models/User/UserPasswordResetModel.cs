namespace UserAPI.Models.User
{
    public class UserPasswordResetModel
    {
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }

        public UserPasswordResetModel(string newPassword, string confirmPassword)
        {
            NewPassword = newPassword;
            ConfirmPassword = confirmPassword;
        }
    }
}
