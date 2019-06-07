// Handling path /api/users/new

import User from "../../models/users/index";
import { createUserDetails, sendJSONResponse, generateValidatorErrorsArray } from "../../utils/utils";
import passwordHash from "password-hash";
import { check, validationResult } from 'express-validator/check';


// Some input controll validators
const validators = [
    check("username").isAlphanumeric().isLength({ max: 50 }),
    check("password").isAlphanumeric(),
    check("email").isEmail()
]

// Handler, the route function
const handler = (req, res) => {
    const errors = validationResult(req).array();
    if(errors.length > 0) {
        sendJSONResponse(res, generateValidatorErrorsArray(errors), false);
        return;
    }

    let newUser = new User();

    newUser.username = req.body.username;
    // Getting the length of the salt from the schema.
    //  deviding by 2 since hex represents each byte as two chars.
    const postedPassword = req.body.password;
    newUser.password = passwordHash.generate(postedPassword, { algorithm: 'sha256' });
    newUser.email = req.body.email;

    newUser.save((err, savedUser) => {
        if(err) {
            sendJSONResponse(res, err, false);
            return;
        }

        const responseBody = createUserDetails(
            savedUser.username,
            savedUser._id
        );
        sendJSONResponse(res, responseBody, true);
    });
};


export default { validators, handler };
