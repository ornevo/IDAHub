// Handling path /api/users/token

import { User } from "../../models/index";
import { createUserDetails, sendJSONResponse } from "../../utils/utils";
import { getJWTToken } from "../../utils/jwt";
import { Protocol } from "../../utils/constants";
import passwordHash from "password-hash";
import { query } from 'express-validator/check';


// Some input controll validators
const validators = [
    query("username").isAlphanumeric().isLength({ max: 50 }),
    query("password").isAlphanumeric()
]

// Handler, the route function
const handler = (req, res) => {
    const username = req.query.username;
    const password = req.query.password;

    // Check if there's a user with the supplied username
    User.find({ username }, (err, foundDocs) => {
        if(err) {
            sendJSONResponse(res, err, false); 
            return;
        } else if(foundDocs.length == 0) {
            sendJSONResponse(res, "User with name " + username + " does not exists.", false, Protocol.Status.UnauthorizedStatusCode);
            return;
        }

        // Check password
        const user = foundDocs[0];

        // If failed to verify
        if(!passwordHash.verify(password, user.password)) {
            sendJSONResponse(res, "Authorization failed.", false, Protocol.Status.UnauthorizedStatusCode);
            return;
        }

        // If here, authorization succeded. Return generated JWT token
        const jwtPayload = createUserDetails(username, user._id);
        const token = getJWTToken(jwtPayload);

        // If failed to create token
        if(!token) {
            sendJSONResponse(res, "Failed to generate token.", false);
            return;
        }

        sendJSONResponse(res, { token }, true);
    });
};


export default { validators, handler };
