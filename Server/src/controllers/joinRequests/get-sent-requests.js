// For requester, get requests yet to be approved or approved but yet to be read
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

    JoinRequests.find({ userId: req.jwt.id, $or: [ {approved:false}, {approveReadByRequester:false} ] }, (err, requests) => {
        if(err || typeof requests != typeof []) {
            sendJSONResponse(res, err, false);
            return;
        }

        const retArr = requests.map(r => ({
            id: r._id.toString(),
            projectId: r.projectId,
            approved: r.approved,
            readByRequester: r.approveReadByRequester
        }));

        sendJSONResponse(res, retArr, true);
    });
}


export default { validators, handler };
