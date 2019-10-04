// For requester, get requests yet to be approved or approved but yet to be read
import { validateAuthToken } from "../middleware";
import { sendJSONResponse, createUserDetails } from "../../utils/utils";
import { Protocol } from "../../utils/constants";
import { JoinRequests, User, Project } from "../../models/index";
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

        // For each entry, we need the project name
        const projectIds = requests.map(r => r.projectId);

        Project.find({ _id: { $in: projectIds }}, (err, projects) => {
            if(err || typeof projects != typeof []) {
                sendJSONResponse(res, err, false);
                return;
            }

            // Create the basic returned arr
            let retArr = requests.map(r => ({
                id: r._id.toString(),
                projectId: r.projectId,
                approved: r.approved,
                readByRequester: r.approveReadByRequester,
                seenByRequester: r.approveSeenByRequester
            }));

            // Richen it by adding the projectName
            retArr = retArr.map(retElem => {
                const foundProject = projects.find(p => p._id.toString() === retElem.projectId.toString());

                // Just default if not found...
                if(!foundProject)
                    retElem.projectName = "Anonymous";
                else
                    retElem.projectName = foundProject.name;

                return retElem;
            });
    
            sendJSONResponse(res, retArr, true);
        })
    });
}


export default { validators, handler };
