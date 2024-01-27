using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Models.Security.Usuario
{
    public class Register
    {
        [Required(ErrorMessage = "Nome de usuário é obrigatório")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Nome é obrigatório")]
        public string? FirstName { get; set; }

        [Required(ErrorMessage = "Sobrenome é obrigatório")]
        public string? LastName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email é obrigatório")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Senha é obrigatório")]
        public string? Password { get; set; }

        [Required(ErrorMessage = "Função é obrigatório")]
        public string? Role { get; set; }
    }
}
