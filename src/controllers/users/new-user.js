// Handling path /api/users/new

import User from "../../models/users/index";
import { createUserDetails, sendJSONResponse } from "../../utils/utils";
import passwordHash from "password-hash";

// Handler
export default (req, res) => {
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
