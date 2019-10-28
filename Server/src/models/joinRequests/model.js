/**
 * Model definition for the Users collection
 */
import mongoose from "mongoose";
import JoinRequestsSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const JoinRequests = mongoose.model(Models.JoinRequests.name, JoinRequestsSchema);

export default JoinRequests;
