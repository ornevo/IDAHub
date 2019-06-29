import { Protocol } from "./constants";


const createUserDetails = (username, id) => ({ username, id })

// Creates project header.
//  ProjectObject should be the project as retrieved from the DB
//  contributersArray should be an array of userDetails of the project contributers
const createProjectHeader = (projectObject, contributorsArray) => (
    {
        name: projectObject.name,
        description: projectObject.description,
        hash: projectObject.description,
        owner: projectObject.owner,
        id: projectObject._id,
        public: projectObject.public,
        contributors: contributorsArray
    }
)

// if statusCode not specified, will set to 200 if isSuccess and 500 otherwise
const sendJSONResponse = (res, body, isSuccess, statusCode=-1) => {
    // Set return status code
    if(statusCode == -1)
        res.status(isSuccess ? 200 : Protocol.Status.FailureStatusCode);
    else
        res.status(statusCode);

    // Set return value
    res.json({
        status: isSuccess ? Protocol.Status.Success : Protocol.Status.Failure,
        body: body 
    });
}

// Transforms the error array returned from express-validator.validationResult into
//  an array of strings
const generateValidatorErrorsArray =
    originalErrsArray => originalErrsArray.map(e => "Error in param '" + e['param'] + "': " + e['msg']);


export { createUserDetails, sendJSONResponse, generateValidatorErrorsArray, createProjectHeader };