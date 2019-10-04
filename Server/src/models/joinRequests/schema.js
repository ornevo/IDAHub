/**
 * Schema definition for the joinReuqests collection.
 */

import { Schema } from "mongoose";
import { Models } from "../../utils/constants";


const JoinRequestsSchema = Schema({
    projectId: {
        type: Schema.Types.ObjectId,
        ref: Models.UserInProject.name,
        required: true,
    },
    ownerId: {
        type: Schema.Types.ObjectId,
        ref: Models.User.name,
        required: true,
    },
    userId: { // User id of the requester
        type: Schema.Types.ObjectId,
        ref: Models.User.name,
        required: true,
    },
    // request states //
    readByOwner: {
        type: Schema.Types.Boolean,
        required: true,
        default: false
    },
    approved: {
        type: Schema.Types.Boolean,
        required: true,
        default: false
    },
    dismissed: {
        type: Schema.Types.Boolean,
        required: true,
        default: false
    },
    approveReadByRequester: {
        type: Schema.Types.Boolean,
        required: true,
        default: false
    },
});

export default JoinRequestsSchema;