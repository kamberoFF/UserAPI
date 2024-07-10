using UserAPI.Models.User;
using UserAPI.Repositories.User;
namespace UserAPI.Services.User
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }
        public async Task<List<UserPublicDataModel>> GetAllUsersAsync()
        {
            return await _userRepository.GetAllUsersAsync();
        }
        public async Task<UserBaseModel> AdminUpdateUserAsync(int id, UserUpdateModel userModel)
        {
            return await _userRepository.AdminUpdateUserAsync(id, userModel);
        }
        public async Task<UserBaseModel> UpdateUserAsync(int id, UserUpdateModel userModel)
        {
            return await _userRepository.UpdateUserAsync(id, userModel);
        }
        public async Task<UserBaseModel> CreateUserAsync(UserCreateModel userModel)
        {
            return await _userRepository.CreateUserAsync(userModel);
        }
        public async Task<UserBaseModel> AdminDeleteUserAsync(int id)
        {
            return await _userRepository.AdminDeleteUserAsync(id);
        }
        public async Task<UserBaseModel> DeleteUserAsync(int id)
        {
            return await _userRepository.DeleteUserAsync(id);
        }
        public async Task<string> SendVerificationEmail(string email)
        {
            return await _userRepository.SendVerificationEmail(email);
        }
        public async Task<string> VerifyEmail(string token)
        {
            return await _userRepository.VerifyEmail(token);
        }
        public async Task<string> SendPasswordResetEmail(string email)
        {
            return await _userRepository.SendPasswordResetEmail(email);
        }
        public async Task<string> ResetPassword(string token, UserPasswordResetModel newPassword)
        {
            return await _userRepository.ResetPassword(token, newPassword);
        }
        public async Task<string> BasicResetPassword(int id, UserBasicPasswordResetModel newPassword)
        {
            return await _userRepository.BasicResetPassword(id, newPassword);
        }
        public async Task<string> UserLogin(UserLoginFormModel userLogin)
        {
            return await _userRepository.UserLogin(userLogin);
        }
    }
}
