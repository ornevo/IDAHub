import { sendJSONResponse, generateValidatorErrorsArray } from "../utils/utils";
import { Protocol } from "../utils/constants";
import { validationResult } from 'express-validator/check';
import { verifyJWTToken } from '../utils/jwt';


// Checks if some errors occurred during params validation, and returns
//  an error response if some did.
export const handleExpressValidatorErrorsMiddleware = (req, res, next) => {
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
export const defaultParamToMiddleware = (fieldName, reqSubObjectName, defaultValue) => {
    return function(req, res, next) {
        req[reqSubObjectName][fieldName] = req[reqSubObjectName][fieldName] || defaultValue;
        next();
    }
}

// Validates the passed JWT, and add the decoded token to req.jwt
// TBH I wrote it as a function returning the middleware instead of
//  simply the middleware itself just to keep a convention with the previous
//  middleware defaultParamToMiddleware
export const validateAuthToken = () => {
    function failValidation(res) {
        sendJSONResponse(res, "Autherization token validation failed.", false, Protocol.Status.UnauthorizedStatusCode);
        return;
    }

    return function(req, res, next) {
        // Get the http header raw string value 
        let autherizationHeader = String(req.get('authorization'));
        if(!autherizationHeader || autherizationHeader.split(" ").length != 2) {
            failValidation(res);
            return;
        }
        
        // Extract the method and token from it
        const [scheme, token] = autherizationHeader.split(" ");
        if(scheme != Protocol.httpAuthorizationScheme || !token) {
            failValidation(res);
            return;
        }

        // Validate the token
        const decodedJWT = verifyJWTToken(token);
        if(!decodedJWT) {
            failValidation(res);
            return;
        }

        // And finally, once validated and decoded, assign to the request
        req.jwt = decodedJWT;

        next();
    }
}