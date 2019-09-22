// Handling path /api/projects/:projectId/session/stop

import { param ,body} from "express-validator/check";
import { Modification} from "../../models/index";
import { getProjectHeaders } from "../../utils/dbhelpers";
import { validateProjectId, validateAuthToken } from "../middleware";
import { Project } from "../../models/index";
import { User } from "../../models/index";
import { UserInProject } from "../../models/index";
import {Session} from "../../models/index";
import { sendJSONResponse, createUserDetails, createProjectHeader } from "../../utils/utils";

// Some input controll validators
const validators = [
     // check the project id
       validateProjectId(),
     // check the authentication
     validateAuthToken()
]

// Handler, the route function
const handler = (req, res) => {
    var mongoose = require('mongoose');
    var myquery = { projectId: mongoose.Types.ObjectId(req.params['projectId']) , userId: req.jwt.id };
    var newvalue = { $set: {endTimestamp: (Math.floor(new Date().getTime()/1000.0)).toString() } };
    //Update the session document
    Session.updateOne(myquery, newvalue, (err, res) => {
        if (err) {
        sendJSONResponse(res, "error", false);
    return;
         }
    });
    sendJSONResponse(res, "OK", true);
};
export default { validators, handler };
