namespace UserAPI.Models.User
{
    public class UserBaseModel
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public string Surname { get; set; }
        public string Role { get; set; }
        public bool Verified { get; set; }
        public string? emailToken { get; set; }
        public string? passwordToken { get; set; }

        public UserPublicDataModel ToUserPublicDataModel()
        {
            return new UserPublicDataModel(Id, Username, Email, Name, Surname, Role, Verified);
        }

        public UserBaseModel(string username, string email, string password, string name, string surname, string role)
        {
            Username = username;
            Email = email;
            //Encrypt password
            Password = password;
            Name = name;
            Surname = surname;
            Role = role;
            Verified = false;
        }
    }
}
