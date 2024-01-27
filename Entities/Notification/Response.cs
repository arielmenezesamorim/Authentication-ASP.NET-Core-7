using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Notification
{
    public class Response
    {
        public int Status { get; set; }
        public string? Message { get; set; }
        public object? Object { get; set; }
    }
}
