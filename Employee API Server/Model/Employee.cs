namespace EmployeeApi.Models
{
    public class Employee
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public int Age { get; set; }
        public int Salary { get; set; }

        //Authentication-related fields
        public string Email {  get; set; }
        public string PasswordHash { get; set;}
        public string Role {  get; set; }

        public string RefreshTokenHash {  get; set; }
        public DateTime? RefreshTokenExpiresAt {  get; set; }
        public  DateTime? RefreshTokenRevokedAt {  get; set; }

    }
}
