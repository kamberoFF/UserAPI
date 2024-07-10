namespace UserAPI.Models.User
{
    public class UserLoginFormModel
    {
        public string Username { get; set; }
        public string Password { get; set; }

        public UserLoginFormModel(string username, string password)
        {
            Username = username;
            //Encrypt password
            Password = password;
        }
    }
}
