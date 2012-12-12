using System.Web.Mvc;

namespace OpenIDRelyingParty.Controllers
{
    public class HomeController : Controller
    {
        /// <summary>
        /// Indexes this instance.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// Secureds this instance.
        /// </summary>
        /// <returns></returns>
        [HttpGet][Authorize]
        public ActionResult Secured()
        {
            return this.View();
        }
    }
}
