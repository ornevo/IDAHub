
import express from 'express';
var router = express.Router();

// import middleware
import { handleExpressValidatorErrorsMiddleware } from "./middleware";

// import handlers
import NewUser from "./users/new-user"; 
import NewProject from "./projects/new-project"; 
import Statistics from "./projects/statistics";
import SearchProjects from "./projects/search-projects";
import AddContributor from "./projects/add-contributor";
import SearchUser from "./users/search-users"; 
import GetUserProjects from "./users/get-user-projects"; 
import GetUserToken from "./users/get-token";
import GetProject from "./projects/get-project";
import JoinRequest from "./joinRequests/new-join-request";
import UpdateJoinRequest from "./joinRequests/update-request";
import GetPendingRequests from "./joinRequests/get-pending-requests";
import GetSentRequests from "./joinRequests/get-sent-requests";
import NewChange from "./Changes Updating/new-change";
import StartSession from  "./Real Time Collaboration/start-session";
import StopSession from  "./Real Time Collaboration/stop-session";
import PullChanges from  "./Real Time Collaboration/pull-changes";


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
defineRoute(router.post.bind(router), "/api/projects/:projectId/join-request", JoinRequest);
defineRoute(router.post.bind(router), "/api/join-requests/:requestId", UpdateJoinRequest);
defineRoute(router.get.bind(router), "/api/users/:userId/pending-requests", GetPendingRequests);
defineRoute(router.post.bind(router), "/api/projects/:projectId/users/:userId", AddContributor);
defineRoute(router.get.bind(router), "/api/users/:userId/sent-requests", GetSentRequests);
defineRoute(router.get.bind(router), "/api/projects/:projectId/statistics", Statistics);
defineRoute(router.get.bind(router), "/api/users/:userId/projects", GetUserProjects);
defineRoute(router.post.bind(router), "/api/projects", NewProject);
defineRoute(router.get.bind(router), "/api/projects", SearchProjects);
defineRoute(router.post.bind(router), "/api/projects/:projectId/push", NewChange);
defineRoute(router.post.bind(router), "/api/projects/:projectId/session/start", StartSession);
defineRoute(router.post.bind(router), "/api/projects/:projectId/session/stop", StopSession);
defineRoute(router.get.bind(router), "/api/projects/:projectId/changes", PullChanges);

export default router;
