import { sendJSONResponse, generateValidatorErrorsArray } from "../utils/utils";
import { Protocol } from "../utils/constants";
import { validationResult } from 'express-validator/check';
import { verifyJWTToken } from '../utils/jwt';
import { Project } from "../models";
import mongoose from 'mongoose';


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

// If projectId is a valid id, adds the project to req.project
export const validateProjectId = () => function(req, res, next){
    const projectId = req.params['projectId'];
    if(typeof projectId !== typeof "" || !mongoose.Types.ObjectId.isValid(projectId)) {
        sendJSONResponse(res, "projectId is not valid.", false);
        return;
    }

    Project.findById(projectId, (err, project) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }
        // If not found
        if(!project._id) {
            sendJSONResponse(res, "Not found", false, Protocol.Status.NotFoundStatusCode);
            return;
        }

        req.project = project;
        next();
    });
}

// Validates the passed JWT, and add the decoded token to req.jwt
// If requireAuth is true, will return unautherized response if fails
//  to approve token. if requireAuth is false, will set req.jwt = undefined
//  and proceed.
// TBH I wrote it as a function returning the middleware instead of
//  simply the middleware itself just to keep a convention with the previous
//  middleware defaultParamToMiddleware
export const validateAuthToken = (requireAuth = true) => {
    function failValidation(req, res, next) {
        if(requireAuth) {
            sendJSONResponse(res, "Autherization token validation failed.", false, Protocol.Status.UnauthorizedStatusCode);
            return;
        } else {
            req.jwt = undefined;
            next();
        }
    }

    return function(req, res, next) {
        // Get the http header raw string value 
        let autherizationHeader = String(req.get('authorization'));
        if(!autherizationHeader || autherizationHeader.split(" ").length != 2) {
            failValidation(req, res, next);
            return;
        }
        
        // Extract the method and token from it
        const [scheme, token] = autherizationHeader.split(" ");
        if(scheme != Protocol.httpAuthorizationScheme || !token) {
            failValidation(req, res, next);
            return;
        }

        // Validate the token
        const decodedJWT = verifyJWTToken(token);
        if(!decodedJWT) {
            failValidation(req, res, next);
            return;
        }

        // And finally, once validated and decoded, assign to the request
        req.jwt = decodedJWT;

        next();
    }
}