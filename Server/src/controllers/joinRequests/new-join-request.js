import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse } from "../../utils/utils";
import { Protocol } from "../../utils/constants";
import { JoinRequests, UserInProject } from "../../models/index";


const validators = [
    validateAuthToken(),
    validateProjectId()
]

const handler = (req, res) => {   
    // req.project got initialized by validateProjectId
    if(!req.project.public) {
        // If he'd be authorized, he wouldn't need to send a join request...
        sendJSONResponse(res, "Unauthorized", false, Protocol.Status.UnauthorizedStatusCode);
        return;
    }

    // Make sure the user isn't already contributor of the project
    UserInProject.findOne({ projectId: req.project._id, userId: req.jwt.id }, (err, user) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }

        // If already contributor, don't send request
        if(user) {
            sendJSONResponse(res, "User already contributor of the project", false);
            return;
        }

        // Make sure the user hasn't sent a request already
        JoinRequests.findOne({ projectId: req.project._id, userId: req.jwt.id }, (err, previousRequest) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }
    
            // If already sent requestm no matter the status of it, don't allow to resent.
            if(previousRequest) {
                sendJSONResponse(res, "Already sent a request.", false);
                return;
            }
    
            // If here, user is authorized and not already a member
            let jRequest = new JoinRequests();
            jRequest.projectId = req.project._id;
            jRequest.ownerId = req.project.owner;
            jRequest.userId = req.jwt.id;
            
            jRequest.save((err, _) => {
                if(err)
                    sendJSONResponse(res, err, false);
                else
                    sendJSONResponse(res, "", true);
            });
        })

    })
}


export default { validators, handler };
