// Handles the api /api/projects/:projectId/users/:userId

import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse } from "../../utils/utils";
import { Protocol } from "../../utils/constants";
import { User, UserInProject } from "../../models/index";


const validators = [
    validateAuthToken(true),
    validateProjectId()
]


const handler = (req, res) => {
    // req.project and req.jwt are initialized by the validators

    // Check if project owner signed in
    if(!req.project || req.project.owner.toString() !== req.jwt.id) {
        sendJSONResponse(res, "Unauthorized", false, Protocol.Status.UnauthorizedStatusCode);
        return;
    }

    // Check if user to add exists
    User.findById(req.params['userId'].toString()).then((userToAdd, err) => {
        if(err) {
            sendJSONResponse(res, "Internal error", false);
            return;
        }

        if(!userToAdd) {
            sendJSONResponse(res, "User passed to add does not exist", false, Protocol.Status.NotFoundStatusCode);
            return;
        }

        // If here, user exists. Check if not already in project
        UserInProject.find({ userId: userToAdd._id, projectId: req.project._id })
            .then((doc, err) => {
                if(err) {
                    sendJSONResponse(res, "Internal error", false);
                    return;
                }
    
                // If already in project finish
                if(doc && doc.length > 0) {
                    sendJSONResponse(res, "", true);
                    return;
                }

                // If here, we need to add
                let toAdd = new UserInProject();
                toAdd.userId = userToAdd._id;
                toAdd.projectId = req.project._id;
                console.log("Adding user in project: user: " + toAdd.userId.toString() + " project: " + toAdd.projectId.toString());
                toAdd.save((err, savedRecord) => {
                    if(err) {
                        sendJSONResponse(res, "Internal error", false);
                        return;
                    }
                    
                    sendJSONResponse(res, "", true);
                })
            })
    });
}


export default { handler, validators };