namespace UserAPI.Models.User
{
    public class UserBasicPasswordResetModel
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }

        public UserBasicPasswordResetModel(string oldPassword, string newPassword, string confirmPassword)
        {
            OldPassword = oldPassword;
            NewPassword = newPassword;
            ConfirmPassword = confirmPassword;
        }
    }
}
