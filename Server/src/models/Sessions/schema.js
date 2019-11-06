/**
 * Schema definition for the Sessions collection.
 */
import { Schema } from "mongoose";
import { Models } from "../../utils/constants";


const SessionSchema = Schema({
    projectId: {
        type: Schema.Types.ObjectId,
        ref: Models.UserInProject.name,
        required: true
    },
    userId: {
        type: Schema.Types.ObjectId,
        ref: Models.User.name,
        required: true
    },
    startTimestamp: {
        type: String,
        required: true
    },
    endTimestamp: {
        type: String,
        default:null
    } 
});

export default SessionSchema;
