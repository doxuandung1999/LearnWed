using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnWeb.BL
{
    public interface ITest
    {
        string Get();
        string GenToken(string userName, string pass);

        string Decode(string token, string key,bool verify = true);
    }
}
