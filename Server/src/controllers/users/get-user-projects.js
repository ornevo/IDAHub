// Handles the api /api/users/:userId/projects

import { validateAuthToken } from "../middleware";

import { UserInProject } from "../../models/index";
import { sendJSONResponse } from "../../utils/utils";
import { getProjectHeaders } from "../../utils/dbhelpers";
import { param } from "express-validator/check";


// Some input controll validators
const validators = [
    validateAuthToken(false),
    param("userId").isString()
]

// Handler, flow is as follows:
//  1. Find all projects the requested user contributes to
//  2. Get those projects' DB records
//  3. For each project, get the list of contributors.
//  4. For each contributer, get its username.
const handler = (req, res) => {
    const userId = req.params.userId;
    const returnPrivateProjects = (req.jwt || {}).id === userId;

    // Find all projects to which the user contributes
    UserInProject.find({ userId: userId }, (err, foundDocs) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }

        // Find the projects DB records
        const searchedProjectIds = foundDocs.map(d => d.projectId);
        getProjectHeaders(searchedProjectIds, (err, projectHeaders) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            if(!returnPrivateProjects)
                projectHeaders = projectHeaders.filter(p => p.public);

            sendJSONResponse(res, projectHeaders, true);
        })
    });
    
};


export default { handler, validators };