import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse, createUserDetails } from "../../utils/utils";
import { Protocol } from "../../utils/constants";
import { JoinRequests, UserInProject } from "../../models/index";


const validators = [
    validateAuthToken()
]


const handler = (req, res) => {   
    const reqId = req.params['requestId'];

    if(!reqId) {
        sendJSONResponse(res, "Invalid request id", Protocol.Status.NotFoundStatusCode);
        return;
    }

    // First, get original request
    JoinRequests.findById(reqId, (err, request) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return
        }
        if(!request) {
            sendJSONResponse(res, "Request not found", Protocol.Status.NotFoundStatusCode);
            return;
        }
        if(req.jwt.id !== request.ownerId.toString() && req.jwt.id !== request.userId.toString()) {
            sendJSONResponse(res, "Unauthorized: You are not a party in the request.", Protocol.Status.UnauthorizedStatusCode);
            return;
        }
        
        // If here, found request. The OR-ing (||) with the original request both allows the client to emit values
        //  and disables flipping a true back to a false.
        const newState = {
            readByOwner: req.body['read-by-owner'] || request.readByOwner,
            approved: req.body['approved'] || request.approved,
            dismissed: req.body['dismissed'] || request.dismissed,
            approveReadByRequester: req.body['approve-read-by-requester'] || request.approveReadByRequester
        }

        // Make sure there's no funny business
        if(Object.values(newState).find(v => typeof v !== typeof false && typeof v !== typeof undefined)) {
            sendJSONResponse(res, "Bad values, only booleans", false);
            return;
        }

        // Make sure is allowed to make requested changes

        // Only the owner can update whether we read the request, and only the owner can dismiss / approve 
        if(request.readByOwner !== newState.readByOwner || request.approved !== newState.approved || request.dismissed !== newState.dismissed)
            if(req.jwt.id !== request.ownerId.toString()) {
                sendJSONResponse(res, "Only project owner can change request owner-read status and dismiss / approve status.", Protocol.Status.UnauthorizedStatusCode);
                return;
            }

        // Only the requester can update whether he read the approve
        if(request.approveReadByRequester !== newState.approveReadByRequester)
            if(req.jwt.id !== request.userId.toString()) {
                sendJSONResponse(res, "Only request initiator can change requester approve-read status.", Protocol.Status.UnauthorizedStatusCode);
                return;
            }

        // Check if this update should trigger adding the requester to contributors
        const isApproveUpdate = !request.approved && newState.approved;

        // We can now safely apply update.
        request.readByOwner = newState.readByOwner;
        request.approved = newState.approved;
        request.dismissed = newState.dismissed;
        request.approveReadByRequester = newState.approveReadByRequester;
        request.save((err, newRequest) => {
            if(err || !newRequest) {
                sendJSONResponse(res, err, false);
                return;
            } else if(!isApproveUpdate) {
                sendJSONResponse(res, "", true);
                return;
            }

            // If here, this update should trigger adding the requester to the project contributors.
            let contribRecord = new UserInProject();
            contribRecord.userId = request.userId;
            contribRecord.projectId = request.projectId;
            contribRecord.save((err, newContribRecord) => {
                if(err || !newContribRecord)
                    sendJSONResponse(res, err, false);
                else
                    sendJSONResponse(res, "", true);
            });
        });
    });
}


export default { validators, handler };
