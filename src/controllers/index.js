import express from 'express';
var router = express.Router();

// import middleware
import { handleExpressValidatorErrorsMiddleware } from "./middleware";

// import handlers
import NewUser from "./users/new-user"; 
import NewProject from "./projects/new-project"; 
import SearchUser from "./users/search-users"; 
import GetUserToken from "./users/get-token";


/*
 * routerFunction could be `router.get/post`
 * route is the string of the route, e.g. "/api/users/new"
 * exportedRoute is `import "./users/new-user"`
**/
function defineRoute(routerFunction, route, exportedRoute) {
  routerFunction(
    route,
    exportedRoute.validators,
    handleExpressValidatorErrorsMiddleware,
    exportedRoute.handler
  );
}


/* GET home page. */
router.get('/', function(req, res) {
  res.json({
    "Message": 'welcome!'
  });
});

/* User apis */
defineRoute(router.post.bind(router), "/api/users", NewUser);
defineRoute(router.get.bind(router), "/api/users/token", GetUserToken);
defineRoute(router.get.bind(router), "/api/users", SearchUser);
defineRoute(router.post.bind(router), "/api/projects", NewProject);

export default router;
