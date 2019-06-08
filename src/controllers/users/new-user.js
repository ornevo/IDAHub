// Handling path /api/users/new

import { User } from "../../models/index";
import { createUserDetails, sendJSONResponse } from "../../utils/utils";
import passwordHash from "password-hash";
import { body } from 'express-validator/check';


// Some input controll validators
const validators = [
    body("username").isAlphanumeric().isLength({ max: 50 }),
    body("password").isAlphanumeric(),
    body("email").isEmail()
]

// Handler, the route function
const handler = (req, res) => {
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
