// Handles the api /api/projects/:projectId

import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse, isAuthorizedToViewProject } from "../../utils/utils";
import { getProjectHeaders } from "../../utils/dbhelpers"
import { Protocol } from "../../utils/constants";


const validators = [
    validateAuthToken(false),
    validateProjectId()
]


const handler = (req, res) => {
    // req.project and req.jwt are initialized by the validators

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

        const projectHeader = projectHeaderInArr[0];
        
        // Only proceed if either public project or private and the authenticated user is either owner or contributor
        if(!req.project.public) {
            if(!isAuthorizedToViewProject(req.jwt, projectHeader)) {
                sendJSONResponse(res, "Unautherizated to view project.", false, Protocol.Status.UnauthorizedStatusCode);
                return;
            }
        }

        sendJSONResponse(res, projectHeader, true);
    });
}


export default { handler, validators };