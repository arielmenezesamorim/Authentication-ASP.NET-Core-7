using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Models.Security.Token
{
    public class RefreshTokenData
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
