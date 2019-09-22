/**
 * Schema definition for the Modifications collection.
 */
import { Schema } from "mongoose";
import { Models } from "../../utils/constants";


const ModificationSchema = Schema({
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
    timestamp: {
        type: String,
        required: true
    },
    eventId: {
        type: Number,
        required: true
    },
    linearAddress: {
        type: Number,
        maxlength: 100,
        default:null
    },
    value: {
        type: String,
        default:null
    },
    labelType: {
        type: String,
        default:null
    },
    commentType: {
        type: String,
        default:null
    },
    offset: {
        type: Number,
        default:null
    },
    variableType: {
        type: String,
        default:null
    },
    name: {
        type: String,
        default:null
    },
    id: {
        type: String,
        default:null
    }
});

export default ModificationSchema;