// Handles the api /api/projects/:projectId

import { validateProjectId, validateAuthToken } from "../middleware";
import { sendJSONResponse, isAuthorizedToViewProject } from "../../utils/utils";
import { getProjectHeaders } from "../../utils/dbhelpers"
import { Protocol, EventTypes } from "../../utils/constants";
import { Modification, Session } from "../../models/index";


const FUNCTION_RELATED_ET = [
    EventTypes.CHANGE_FUNCTION_NAME_ID,
    EventTypes.NEW_FUNCTION_ID
]

const VARIABLE_RELATED_ET = [
    EventTypes.CHANGE_GLOBAL_VARIABLE_NAME_ID,
    EventTypes.CREATE_STRUCT_VARIABLE_ID,
    EventTypes.CHANGE_STRUCT_NAME_ID,
    EventTypes.CREATE_ENUM_ITEM_ID,
    EventTypes.CREATE_ENUM_ITEM_ID,
    EventTypes.CHANGE_ENUM_ITED_ID,
    EventTypes.CHANGE_ENUM_NAME_ID
]

const COMMENT_RELATED_ET = [
    EventTypes.SET_COMMENT_ID
]

const LABEL_REALTED_ET = [
    EventTypes.SET
]


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

        // If here, we are authenticated and allowed to view project.
        // For large projects this will suck performance wise, but this project will never hit production so...
        Modification.find({ projectId: req.project._id }, (err, modificationsArr) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            // Start collecting response fields
            const modifications = modificationsArr.length;
            const functions = modificationsArr.filter(m => FUNCTION_RELATED_ET.includes(m.eventId)).length;
            const variables = modificationsArr.filter(m => VARIABLE_RELATED_ET.includes(m.eventId)).length;
            const comments = modificationsArr.filter(m => COMMENT_RELATED_ET.includes(m.eventId)).length;
            const labels = modificationsArr.filter(m => LABEL_REALTED_ET.includes(m.eventId)).length;

            // Get the number of online contributors
            Session.find({ projectId: req.project._id, endTimestamp: null }, (err, activeSessions) => {
                if(err) {
                    sendJSONResponse(res, err, false);
                    return;
                }

                const onlineCount = activeSessions.length;

                sendJSONResponse(res, { modifications, functions, variables, comments, labels, onlineCount }, true);
            })

        })

    });
}


export default { handler, validators };