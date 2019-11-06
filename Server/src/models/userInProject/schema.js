/**
 * Schema definition for the Projects collection.
 */

import { Schema } from "mongoose";
import { Models } from "../../utils/constants";


const UserInProjectSchema = Schema({
    projectId: {
        type: Schema.Types.ObjectId,
        ref: Models.UserInProject.name,
        required: true,
    },
    userId: {
        type: Schema.Types.ObjectId,
        ref: Models.User.name,
        required: true,
    }
});

export default UserInProjectSchema;