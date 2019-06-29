// Handling path /api/users/new

import { Project } from "../../models/index";
import { User } from "../../models/index";
import { UserInProject } from "../../models/index";
import { validateAuthToken } from "../middleware"; 
import { sendJSONResponse, createUserDetails, createProjectHeader } from "../../utils/utils";
import { body } from 'express-validator/check';


// Define a custom `project-header.contributors` validation, as it is defined in the design doc
function customContributorsValidator(contributors) {
    if(typeof contributors !== typeof [])
        return Promise.reject("contributors is not an array.");
 
    return Promise.all(contributors.map(userDetails => {
        // If one of the user-details fields isn't provided, reject validation
        if((userDetails.username && userDetails.id) === undefined)
            return Promise.reject("One of the supplied contributers' user-details isn't valid.");
     
        // Now check the user exists
        return User.findById(userDetails.id).then(foundUser => {
            if(!foundUser || foundUser.username != userDetails.username)
                return Promise.reject("User details with id " + userDetails.id + " and name " + userDetails.username + " does not match any user.");
        });
    }));
}

const HASH_HEX_ALLOWED_CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                                'a', 'b', 'c', 'd', 'e', 'f',
                                'A', 'B', 'C', 'D', 'E', 'F'];


// Some input controll validators
const validators = [
    validateAuthToken(),
    body("project-header").exists(),
    body("project-header.name").isString().isLength({ min: 1, max: 500 }),
    body("project-header.description").isString().isLength({ max: 10000 }),
    body("project-header.hash").isWhitelisted(HASH_HEX_ALLOWED_CHARS).isLength({ min: 32, max: 32 }),
    body("project-header.public").isBoolean(),
    body("project-header.contributors").custom(customContributorsValidator)
]

// Handler, the route function
const handler = (req, res) => {
    const passedProjectHeader = req.body["project-header"];
    let newProject = new Project();

    newProject.name = passedProjectHeader.name;
    newProject.description = passedProjectHeader.description;
    newProject.hash = passedProjectHeader.hash.toLowerCase();
    
    // For now allow all users to create public project, maybe in the future
    //  only allow "premium" users or something.
    newProject.public = passedProjectHeader.public;

    newProject.owner = req.jwt.id;
    
    // Add project
    newProject.save((err, savedProject) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }

        let contributors = passedProjectHeader.contributors;
        
        // If save succeeded, continue to add contributers in UserInProjects.
        // Before adding, add the project owner to the contributers
        const ownerUserCred = req.jwt;
        if(!contributors.find(u => u.id == ownerUserCred.id))
            contributors.push(createUserDetails(ownerUserCred.username, ownerUserCred.id));

        const contributorsUserInProjectRecords = contributors.map(c => ({ userId: c.id, projectId: savedProject._id }));

        // Save the contributors
        UserInProject.insertMany(contributorsUserInProjectRecords, (err, docs) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            const responseBody = {"project-header": createProjectHeader(savedProject, contributors) }
            sendJSONResponse(res, responseBody, true);
        });
    });
};


export default { validators, handler };
