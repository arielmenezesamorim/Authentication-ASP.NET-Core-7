using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Models.Security.Usuario
{
    public class Login
    {
        [Required(ErrorMessage = "Email é obrigatório")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Senha é obrigatório")]
        public string? Password { get; set; }
    }
}
