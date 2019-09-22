// Handling path /api/projects/:projectId/session/start

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
    let newSession=new Session();
    newSession.projectId=mongoose.Types.ObjectId(req.params['projectId']);
    const a=req.jwt;
    newSession.userId = a.id;
    newSession.startTimestamp = (Math.floor(new Date().getTime()/1000.0)).toString();
    newSession.endTimestamp=null;

    //Add Session
    newSession.save((err, savedSession) => {
        if(err) {
            sendJSONResponse(res, "error", false);
            return;
        }
        sendJSONResponse(res, "OK", true);
    });
};
export default { validators, handler };