// Handles the api /api/projects/:projectId

import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse } from "../../utils/utils";
import { getProjectHeaders } from "../../utils/dbhelpers"
import { Protocol } from "../../utils/constants";


const validators = [
    validateAuthToken(false),
    validateProjectId()
]


const handler = (req, res) => {    
    // Only proceed if either public project or private and the owner is authenticated
    // req.project and req.jwt are initialized by the validators
    if(!req.project.public && (!req.jwt || req.jwt.id != req.project.owner.toString())) {
        sendJSONResponse(res, "Unautherizated to view project.", false, Protocol.Status.UnauthorizedStatusCode);
        return;
    }

    // Even though validateProjectId has initialized our req.project, it only initializes
    //  is with the project records in the Project DB itslef, not the full project-header.
    // Here we get the whole project header.
    getProjectHeaders([req.project._id], (err, projectHeaderInArr) => {
        // No reason for the length check, though doesn't hurt.
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }
        if(projectHeaderInArr.length != 1) {
            sendJSONResponse(res, "Internal error.", false);
            return;
        }


        sendJSONResponse(res, projectHeaderInArr, true);
    });
}


export default { handler, validators };