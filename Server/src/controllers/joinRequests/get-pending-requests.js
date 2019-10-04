import { validateAuthToken } from "../middleware";
import { sendJSONResponse, createUserDetails } from "../../utils/utils";
import { Protocol } from "../../utils/constants";
import { JoinRequests, User } from "../../models/index";
import { getProjectHeaders } from "../../utils/dbhelpers";


const validators = [
    validateAuthToken()
]

const handler = (req, res) => {   
    const requestedUserId = req.params['userId'];

    if(!requestedUserId || requestedUserId !== req.jwt.id) {
        // If he'd be authorized, he wouldn't need to send a join request...
        sendJSONResponse(res, "Unauthorized", false, Protocol.Status.UnauthorizedStatusCode);
        return;
    }

    // Get all requests the user hasn't resolved yet
    JoinRequests.find({ ownerId: req.jwt.id, $and: [ {approved:false}, {dismissed:false} ] }, (err, requests) => {
        if(err || typeof requests != typeof []) {
            sendJSONResponse(res, err, false);
            return;
        }

        if(requests.length === 0) {
            sendJSONResponse(res, [], true);
            return;
        }

        const requestedProjectIds = requests.map(r => r.projectId);
        const requestersIds = requests.map(r => r.userId);

        // Get project header of the returned project
        getProjectHeaders(requestedProjectIds, (err, projectHeaders) => {
            if(err || !projectHeaders || typeof projectHeaders !== typeof []) {
                sendJSONResponse(res, err, false);
                return;
            }

            // Get user-details of requester
            User.find({ _id: { $in: requestersIds } }, (err, requesters) => {
                if(err || !requesters || typeof requesters !== typeof []) {
                    sendJSONResponse(res, err, false);
                    return;
                }

                // Now we have all the information we need, and we can start constructing the result.
                let retArr = [];

                requests.forEach(request => {
                    // Check if we obtained the project header, skip if not
                    const currProjectHeader = projectHeaders.find(ph => ph.id.toString() === request.projectId.toString());
                    if(!currProjectHeader)
                        return;

                    // Check if we obtained the user initiating the request, skip if not
                    const currRequesterObject = requesters.find(rqter => rqter._id.toString() === request.userId.toString());
                    if(!currRequesterObject)
                        return

                    // Add the join-request-header
                    retArr.push({
                        id: request._id.toString(),
                        project: currProjectHeader,
                        requester: createUserDetails(currRequesterObject.username, currRequesterObject._id.toString()),
                        readByOwner: request.readByOwner,
                        approved: request.approved,
                        dismissed: request.dismissed
                    });
                });

                sendJSONResponse(res, retArr, true);
            })
        })
    })
}


export default { validators, handler };
