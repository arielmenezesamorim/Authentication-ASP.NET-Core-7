using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Constant
{
    public class StatusCode
    {
        //Foram criadas apenas as algumas, fica a seu criterio criar as que você for usar
        //Successful Responses
        public const int Ok = 200;
        public const int Created = 201;
        public const int Accepted = 202;

        //Client error responses
        public const int BadRequest = 400;
        public const int Unauthorized = 401;
        public const int Forbidden = 403;
    }
}
