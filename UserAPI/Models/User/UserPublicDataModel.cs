namespace UserAPI.Models.User
{
    public class UserPublicDataModel
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
        public string Surname { get; set; }
        public string Role { get; set; }
        public bool Verified { get; set; }

        public UserPublicDataModel(int id, string username, string email, string name, string surname, string role, bool verified)
        {
            Id = id;
            Username = username;
            Email = email;
            Name = name;
            Surname = surname;
            Role = role;
            Verified = verified;
        }
    }
}
