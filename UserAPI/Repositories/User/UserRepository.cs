using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using UserAPI.Models.User;
using UserAPI.Services.Encryption;
namespace UserAPI.Repositories.User
{
    public class UserRepository : IUserRepository
    {
        private readonly UserContext db;
        private readonly IEncryptionService _encryptionService;
        byte[] key = new byte[1] { 0x00 };
        private readonly string senderMail = "drug";
        private readonly string senderPassword = "put";

        public UserRepository(UserContext context, IEncryptionService encryptionService)
        {
            db = context;
            _encryptionService = encryptionService;
        }

        public async Task<List<UserPublicDataModel>> GetAllUsersAsync()
        {
            List<UserPublicDataModel> users = new List<UserPublicDataModel>();

            foreach (var user in await db.Users.ToListAsync())
                users.Add(user.ToUserPublicDataModel());

            return users;
        }

        public async Task<UserBaseModel> AdminUpdateUserAsync(int id, UserUpdateModel userModel)
        {
            var user = await db.Users.FindAsync(id);
            if (user == null)
            {
                return null;
            }

            user.Username = userModel.Username;
            user.Email = userModel.Email;
            //Encrypt password
            user.Password = _encryptionService.Encrypt(userModel.Password);
            user.Name = userModel.Name;
            user.Surname = userModel.Surname;
            user.Role = userModel.Role;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            return user;
        }
        public async Task<UserBaseModel> UpdateUserAsync(int id, UserUpdateModel userModel)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == userModel.Username);

            if (user == null)
            {
                return null;
            }

            else if (id != user.Id)
            {
                return null;
            }

            user.Username = userModel.Username;
            user.Email = userModel.Email;
            //Encrypt password
            user.Password = _encryptionService.Encrypt(userModel.Password);
            user.Name = userModel.Name;
            user.Surname = userModel.Surname;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            return user;
        }

        public async Task<UserBaseModel> CreateUserAsync(UserCreateModel userModel)
        {
            userModel.Password = _encryptionService.Encrypt(userModel.Password);

            var user = userModel.ToUserBaseModel();

            db.Users.Add(user);
            await db.SaveChangesAsync();

            return user;
        }

        public async Task<UserBaseModel> AdminDeleteUserAsync(int id)
        {
            var user = await db.Users.FindAsync(id);
            if (user == null)
            {
                return null;
            }

            db.Users.Remove(user);
            await db.SaveChangesAsync();

            return user;
        }

        public async Task<UserBaseModel> DeleteUserAsync(int id)
        {
            var user = await db.Users.FindAsync(id);
            if (user == null)
            {
                return null;
            }

            db.Users.Remove(user);
            await db.SaveChangesAsync();

            return user;
        }

        public async Task<string> SendVerificationEmail(string email)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                return "User not found!";
            }
            else if (user.Verified)
            {
                return "User already verified!";
            }

            var token = _encryptionService.Encrypt(user.Email);
            token = ToURLSafeString(token);
            user.emailToken = token;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            //Create email
            var senderEmail = new MailAddress(senderMail, "Kamberoff Services");
            var receiverEmail = new MailAddress(email, user.Username);
            var password = senderPassword;
            var subject = "Email Verification";
            var link = $"https://localhost:7296/api/user/verifyEmail/{token}";
            var body = $"Click Here {link} to Verify Email";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(senderEmail.Address, password)
            };

            var message = new MailMessage(senderEmail, receiverEmail)
            {
                Subject = subject,
                Body = body
            };

            //Send email
            smtp.Send(message);

            return "Email sent";
        }

        public async Task<string> VerifyEmail(string token)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.emailToken == token);
            if (user == null)
            {
                return "User not found!";
            }

            user.Verified = true;
            user.emailToken = null;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            return "Email verified!";
        }

        public async Task<string> SendPasswordResetEmail(string email)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                return "User not found!";
            }

            var token = _encryptionService.Encrypt(user.Email);
            token = ToURLSafeString(token);
            user.passwordToken = token;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            //Create email
            var senderEmail = new MailAddress(senderMail, "Kamberoff Services");
            var receiverEmail = new MailAddress(email, user.Username);
            var password = senderPassword;
            var subject = "Password Reset";
            var link = $"https://localhost:7296/api/user/resetPassword/{token}";
            var body = $"Click Here {link} to Reset Password";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(senderEmail.Address, password)
            };

            var message = new MailMessage(senderEmail, receiverEmail)
            {
                Subject = subject,
                Body = body
            };

            //Send email
            smtp.Send(message);

            return "Email sent";
        }

        public async Task<string> ResetPassword(string token, UserPasswordResetModel newPassword)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.passwordToken == token);
            if (user == null)
            {
                return "User not found!";
            }

            user.Password = _encryptionService.Encrypt(newPassword.NewPassword);
            user.passwordToken = null;

            db.Users.Update(user);
            await db.SaveChangesAsync();

            return "Password Reset!";
        }

        public async Task<string> BasicResetPassword(int id, UserBasicPasswordResetModel newPassword)
        {
            var user = await db.Users.FindAsync(id);
            if (user == null)
            {
                return "User not found!";
            }
            else if (user.Password != _encryptionService.Encrypt(newPassword.OldPassword))
            {
                return "Old Password is Incorrect!";
            }

            user.Password = _encryptionService.Encrypt(newPassword.NewPassword);

            db.Users.Update(user);
            await db.SaveChangesAsync();

            return "Password Reset!";
        }
        public async Task<string> UserLogin(UserLoginFormModel userLogin)
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == userLogin.Username);
            if (user == null)
            {
                return "User not found!";
            }

            else if (user.Password != _encryptionService.Encrypt(userLogin.Password))
            {
                return "Wrong password!";
            }

            else if (!user.Verified)
            {
                return "Email not verified!";
            }

            //Login successful
            return await GenerateJWTToken(user);
        }
        public async Task<string> GenerateJWTToken(UserBaseModel userBaseModel)
        {
            var claims = new List<Claim>
            {
                new Claim("id", userBaseModel.Id.ToString()),
                new Claim(ClaimTypes.Name, userBaseModel.Username),
                new Claim(ClaimTypes.Role, userBaseModel.Role)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var readyToken = $"Bearer {tokenHandler.WriteToken(token)}";

            return readyToken;
        }

        private string ToURLSafeString(string input)
        {
            return input.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }
    }
}
