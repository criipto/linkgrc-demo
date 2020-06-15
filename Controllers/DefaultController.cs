using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace LinkGRC.Controllers
{
    public class DefaultController : ApiController
    {
        [Authorize]
        public IHttpActionResult Get()
        {
            return Ok($"Hi there: {User.Identity.Name}");
        }
    }
}
