using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using UserAPI.Models.User;
using UserAPI.Services.User;

namespace UserAPI.Controllers.User
{
    [Route("api/user")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        //GET: api/admin/user/all
        [Authorize(Roles = "admin")]
        [HttpGet("admin/user/all")]
        public async Task<List<UserPublicDataModel>> GetAllUsers()
        {
            return await _userService.GetAllUsersAsync();
        }
        //PUT: api/admin/user/update/{id}
        [Authorize(Roles = "admin")]
        [HttpPut("admin/user/update/{id}")]
        public async Task<UserBaseModel> AdminUpdateUser(int id, UserUpdateModel newUser)
        {
            return await _userService.AdminUpdateUserAsync(id, newUser);
        }

        //PUT: api/user/update/{id}
        [Authorize]
        [HttpPut("update")]
        public async Task<UserBaseModel> UpdateUser(UserUpdateModel newUser)
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            int id = 0;

            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);

                // Decode and read the token
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                id = int.Parse(jwtToken.Claims.FirstOrDefault(claim => claim.Type == "id")?.Value);

                if (id == 0)
                {
                    return null;
                }
            }

            return await _userService.UpdateUserAsync(id, newUser);
        }

        //POST: api/user/create
        [HttpPost("create")]
        public async Task<UserBaseModel> CreateUser(UserCreateModel newUser)
        {
            return await _userService.CreateUserAsync(newUser);
        }

        //DELETE: api/admin/user/delete/{id}
        [Authorize(Roles = "admin")]
        [HttpDelete("admin/user/delete/{id}")]
        public async Task<UserBaseModel> AdminDeleteUser(int id)
        {
            return await _userService.DeleteUserAsync(id);
        }
        //DELETE: api/user/delete
        [Authorize]
        [HttpDelete("delete")]
        public async Task<UserBaseModel> DeleteUser()
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            int id = 0;

            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);

                // Decode and read the token
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                id = int.Parse(jwtToken.Claims.FirstOrDefault(claim => claim.Type == "id")?.Value);

                if (id == 0)
                {
                    return null;
                }
            }

            return await _userService.DeleteUserAsync(id);
        }

        //GET: api/user/sendVerificationEmail/{email}
        [HttpGet("sendVerificationEmail/{email}")]
        public async Task<string> SendVerificationEmail(string email)
        {
            return await _userService.SendVerificationEmail(email);
        }
        //GET: api/user/verifyEmail/{token}
        [HttpGet("verifyEmail/{token}")]
        public async Task<string> VerifyEmail(string token)
        {
            return await _userService.VerifyEmail(token);
        }
        //GET: api/user/sendPasswordResetEmail/{email}
        //Fix it with frontend
        [HttpGet("sendPasswordResetEmail/{email}")]
        public async Task<string> SendPasswordResetEmail(string email)
        {
            return await _userService.SendPasswordResetEmail(email);
        }
        //POST: api/user/resetPassword/{token}
        [HttpPost("resetPassword/{token}")]
        public async Task<string> ResetPassword(string token, UserPasswordResetModel newPassword)
        {
            return await _userService.ResetPassword(token, newPassword);
        }
        //POST: api/user/changePassword
        [Authorize]
        [HttpPost("changePassword")]
        public async Task<string> ChangePassword(UserBasicPasswordResetModel passwordChange)
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            int id = 0;

            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);

                // Decode and read the token
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                id = int.Parse(jwtToken.Claims.FirstOrDefault(claim => claim.Type == "id")?.Value);

                if (id == 0)
                {
                    return null;
                }
            }

            return await _userService.BasicResetPassword(id, passwordChange);
        }
        //POST: api/user/login
        [HttpPost("login")]
        public async Task<string> UserLogin(UserLoginFormModel userLogin)
        {
            return await _userService.UserLogin(userLogin);
        }
    }
}
