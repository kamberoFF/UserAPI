namespace UserAPI.Models.User
{
    public class UserCreateModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public string Surname { get; set; }
        public string Role { get; set; }

        public UserBaseModel ToUserBaseModel()
        {
            return new UserBaseModel(Username, Email, Password, Name, Surname, Role);
        }

        public UserCreateModel(string username, string email, string password, string name, string surname, string role)
        {
            Username = username;
            Email = email;
            //Encrypt password
            Password = password;
            Name = name;
            Surname = surname;
            Role = role;
        }
    }
}
