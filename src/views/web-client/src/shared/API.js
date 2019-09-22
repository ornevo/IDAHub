// Contains some api functions
import axios from 'axios';
import { safeget } from "./Utils";
import * as HttpStatus from 'http-status-codes'


const URL = "http://localhost";


// This wraps the promise so that from success response it extracts the body,
//  and from an error it extracts an object: {statusCode: num, body: {}}
function _wrap_api_promise(promise) {
    return promise
        .then(resp => (safeget(['data', 'body'], resp) || {}) )
        .catch(error => Promise.reject({
                statusCode: (safeget(['response', 'status'], error) || HttpStatus.INTERNAL_SERVER_ERROR),
                body: (safeget(['response', 'data', 'body'], error) || safeget(['response', 'data'], error) || ""),
        }));
}

function __auth_key_to_headers(authKey) {
    return {
        "Authorization": "Bearer "+  authKey
    }
}

// Returns a promise 
export const login = ({username, password}) => {
    return _wrap_api_promise(
        axios.get(URL + "/api/users/token", {params: {username, password}})
    );
}

export const signup = ({username, password, email}) => {
    // Since the 
    return _wrap_api_promise(
        axios.post(URL + "/api/users", {username, password, email})
    ).then(respBody => {
        // Since the signup response doesn't contain the password, but we want to signin
        //  right after signup, we'll "enrich" the response with the password here
        respBody.password = password;
        return respBody;
    });
}

export const searchUsersByUsername = (username) => {
    return _wrap_api_promise(
        axios.get(URL + "/api/users", {params: {name: username}})
    );
}

export const newProject = (authApiKey, projectName, projectDescription, isPrivate, contributors, reversedFileHash) => {
    const params = {
        "project-header": {
            name: projectName,
            description: projectDescription,
            hash: reversedFileHash,
            contributors,
            public: !isPrivate
        }
    };

    return _wrap_api_promise(
        axios.post(URL + "/api/projects", params, { headers: __auth_key_to_headers(authApiKey) })
    );
}

export const getUserProjects = (userId, authApiKey=null) => {
    const headers = authApiKey ? __auth_key_to_headers(authApiKey) : null;

    return _wrap_api_promise(
        axios.get(URL + "/api/users/" + userId + "/projects", { headers })
    );
}

export const usersSearch = (query) => {
    return _wrap_api_promise(
        axios.get(URL + "/api/users", { params: { name: query } })
    );
}

export const projectsSearch = (query, authApiKey=null) => {
    const headers = authApiKey ? __auth_key_to_headers(authApiKey) : null;

    return _wrap_api_promise(
        axios.get(URL + "/api/projects", { params: { query }, headers })
    );
}