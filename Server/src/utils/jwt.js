// Some jwt helper functions
// Based on this blog post: https://medium.com/@siddharthac6/json-web-token-jwt-the-right-way-of-implementing-with-node-js-65b8915d550e
import { JWTSettings } from './constants';
import { sign, verify, decode } from 'jsonwebtoken';
import { readFileSync } from 'fs';


const getPublicKey = () => readFileSync(JWTSettings.publicKeyPath, 'utf8');
const getPrivateKey = () => readFileSync(JWTSettings.privateKeyPath, 'utf8');

// In the signing and verifying options theres an 'audience' field, which should be
//  filled with the username to which we issue the token. This function simply fills
//  the 'audience' field.
const settingsForAudience = (settings, audience) => Object.assign(settings, { audience }); 

// Returns undefined if callback throws an error, and returns callback() if not.
const safeInvoke = (callback) => {
    var ret;
    try {
        ret = callback();
    } catch (error) {
        ret = undefined;
    }
    return ret;
}


// Returns the generated token on success, {} of failure 
// The payload of the jwt token is user-details as returned by utils.createUserDetails
const getJWTTokenInternal = (userDetails) => 
    sign(userDetails, getPrivateKey(), settingsForAudience(JWTSettings.SigningSettings, userDetails.username));

// Returns the decoded token on success, {} of failure 
const verifyJWTTokenInternal = 
    (token) => verify(token, getPublicKey(), settingsForAudience(JWTSettings.VerifyingSettings, decode(token).username));


export const getJWTToken = (userDetails) => safeInvoke(() => getJWTTokenInternal(userDetails));
export const verifyJWTToken = (token) => safeInvoke(() => verifyJWTTokenInternal(token));
