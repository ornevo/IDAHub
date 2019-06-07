import { Protocol } from "./constants";


const createUserDetails = (username, id) => ({ username, id })

const sendJSONResponse = (res, body, isSuccess = true) => {
    res.status(isSuccess ? 200 : Protocol.Status.FailureStatusCode);
    res.json({
        status: isSuccess ? Protocol.Status.Success : Protocol.Status.Failure,
        body: body 
    });
}

// Transforms the error array returned from express-validator.validationResult into
//  an array of strings
const generateValidatorErrorsArray =
    originalErrsArray => originalErrsArray.map(e => "Error in param '" + e['param'] + "': " + e['msg']);


export { createUserDetails, sendJSONResponse, generateValidatorErrorsArray };