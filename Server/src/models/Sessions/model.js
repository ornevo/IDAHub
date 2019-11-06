/**
 * Model definition for the Sessions collection
 */
import mongoose from "mongoose";
import SessionSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const  Session= mongoose.model(Models.Session.name, SessionSchema);

export default Session;


