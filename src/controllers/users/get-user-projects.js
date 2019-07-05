// Handles the api /api/users/:userId/projects
// Handling path /api/users?name=<query>&page=<pagenum>

import { validateAuthToken } from "../middleware";

import { Project, User, UserInProject } from "../../models/index";
import { sendJSONResponse, createUserDetails, createProjectHeader } from "../../utils/utils";
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
        Project.find({ _id: { $in: searchedProjectIds } }, (err, projects) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            if(!returnPrivateProjects)
                projects = projects.filter(p => p.public);

            // The project header contains each project's contributors,
            //  so we need to gather all contributors in the  projects we return
            const returnedProjectIds = projects.map(p => p._id);

            UserInProject.find({ projectId: { $in: returnedProjectIds } }, (err, uInP) => {
                if(err) {
                    sendJSONResponse(res, err, false);
                    return;
                }

                // Lastly, we need the username of each contributer for the contributer arrays
                // The "new Set" trick is used to prevent duplicates, make the array unique
                const userIdsToFind = [...new Set(uInP.map(cont => cont.userId))];

                User.find({ _id: { $in : userIdsToFind } }, (err, allContributorsRecords) => {
                    if(err) {
                        sendJSONResponse(res, err, false);
                        return;
                    }

                    // Build the project-header array
                    let responseBody = [];
                    projects.forEach(project => {
                        // The userInProject records for the current project
                        const currUsersInProject = uInP.filter(uip => uip.projectId.equals(project._id));
                        
                        // The current projects' contributors' records
                        const currContribsRecords = currUsersInProject.map(uip => allContributorsRecords.find(c => c._id.equals(uip.userId)));

                        // The user-header of each contributer
                        const contributors = currContribsRecords.map(c => createUserDetails(c.username, c._id));

                        const currProjectHeader = createProjectHeader(project, contributors);
                        responseBody.push(currProjectHeader);
                    });

                    sendJSONResponse(res, responseBody, true);
                })
            })
        });
    });
    
};


export default { handler, validators };