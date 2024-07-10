using UserAPI.Models.User;

namespace UserAPI.Services.User
{
    public interface IUserService
    {
        //Admin only
        Task<List<UserPublicDataModel>> GetAllUsersAsync();
        //Admin
        Task<UserBaseModel> AdminUpdateUserAsync(int id, UserUpdateModel userModel);
        //User
        Task<UserBaseModel> UpdateUserAsync(int id, UserUpdateModel userModel);
        //Everyone
        Task<UserBaseModel> CreateUserAsync(UserCreateModel userModel);
        //Admin
        Task<UserBaseModel> AdminDeleteUserAsync(int id);
        //User
        Task<UserBaseModel> DeleteUserAsync(int id);
        //Everyone
        Task<string> SendVerificationEmail(string email);
        //Everyone
        Task<string> VerifyEmail(string token);
        //Everyone
        Task<string> SendPasswordResetEmail(string email);
        //Everyone
        //Fix it with frontend
        Task<string> ResetPassword(string token, UserPasswordResetModel newPassword);
        //Everyone
        Task<string> BasicResetPassword(int id, UserBasicPasswordResetModel newPassword);
        //Everyone
        Task<string> UserLogin(UserLoginFormModel userLogin);
    }
}
