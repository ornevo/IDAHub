import { Project, User, UserInProject } from "../models/index";
import { createUserDetails, createProjectHeader } from "./utils";


// Builds project-headers as defined in the docs.
// Callback's signature should be callback(err, projectHeaders).
export const getProjectHeaders = (projectIds, callback) => {

    Project.find({ _id: { $in: projectIds } }, (err, projects) => {
        if(err) {
            callback(err, undefined);
            return;
        }

        // The project header contains each project's contributors,
        //  so we need to gather all contributors in the  projects we return
        const returnedProjectIds = projects.map(p => p._id);

        UserInProject.find({ projectId: { $in: returnedProjectIds } }, (err, uInP) => {
            if(err) {
                callback(err, undefined);
                return;
            }

            // Lastly, we need the username of each contributer for the contributer arrays
            // The "new Set" trick is used to prevent duplicates, make the array unique
            const userIdsToFind = [...new Set(uInP.map(cont => cont.userId))];

            User.find({ _id: { $in : userIdsToFind } }, (err, allContributorsRecords) => {
                if(err) {
                    callback(err, undefined);
                    return;
                }

                // Build the project-header array
                let projectHeaders = [];
                projects.forEach(project => {
                    // The userInProject records for the current project
                    const currUsersInProject = uInP.filter(uip => uip && uip.projectId.equals(project._id));

                    // The current projects' contributors' records
                    const currContribsRecords = currUsersInProject.map(uip => allContributorsRecords.find(c => c._id.equals(uip.userId)));

                    // The user-header of each contributer
                    const contributors = currContribsRecords.filter(c => c).map(c => createUserDetails(c.username, c._id));

                    const currProjectHeader = createProjectHeader(project, contributors);
                    projectHeaders.push(currProjectHeader);
                });

                callback(undefined, projectHeaders);
            })
        })
    });
}