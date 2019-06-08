import { sendJSONResponse, generateValidatorErrorsArray } from "../utils/utils";
import { validationResult } from 'express-validator/check';


// Checks if some errors occurred during params validation, and returns
//  an error response if some did.
const handleExpressValidatorErrorsMiddleware = (req, res, next) => {
    const errors = validationResult(req).array();
    if(errors.length > 0) {
        sendJSONResponse(res, generateValidatorErrorsArray(errors), false);
        return;
    }
    next();
}


export { handleExpressValidatorErrorsMiddleware }