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


/*
 * A middleware to give default values to param.
 * If, for example, we want to give req.query.page a default value of 0:
 *  fieldName is the field name, in the example 'page'
 *  reqSubObjectName is the way the parameter is passed. In the exmaple, 'query'
 *  defaultValue is the default value we want to give it.
**/
const defaultParamToMiddleware = (fieldName, reqSubObjectName, defaultValue) => {
    return function(req, res, next) {
        req[reqSubObjectName][fieldName] = req[reqSubObjectName][fieldName] || defaultValue;
        next();
    }
}


export { handleExpressValidatorErrorsMiddleware, defaultParamToMiddleware }