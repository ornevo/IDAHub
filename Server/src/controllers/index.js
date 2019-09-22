
import express from 'express';
var router = express.Router();

// import middleware
import { handleExpressValidatorErrorsMiddleware } from "./middleware";

// import handlers
import NewUser from "./users/new-user"; 
import NewProject from "./projects/new-project"; 
import SearchProjects from "./projects/search-projects";
import SearchUser from "./users/search-users"; 
import GetUserProjects from "./users/get-user-projects"; 
import GetUserToken from "./users/get-token";
import GetProject from "./projects/get-project";
import NewChange from "./Changes Updating/new-change";
import StartSession from  "./Real Time Collaboration/start-session";
import StopSession from  "./Real Time Collaboration/stop-session";


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
defineRoute(router.get.bind(router), "/api/users", SearchUser);
defineRoute(router.get.bind(router), "/api/users/token", GetUserToken);
defineRoute(router.get.bind(router), "/api/projects/:projectId", GetProject);
defineRoute(router.get.bind(router), "/api/users/:userId/projects", GetUserProjects);
defineRoute(router.post.bind(router), "/api/projects", NewProject);
defineRoute(router.get.bind(router), "/api/projects", SearchProjects);
defineRoute(router.post.bind(router), "/api/projects/:projectId/push", NewChange);
defineRoute(router.post.bind(router), "/api/projects/:projectId/session/start", StartSession);
defineRoute(router.post.bind(router), "/api/projects/:projectId/session/stop", StopSession);

export default router;
