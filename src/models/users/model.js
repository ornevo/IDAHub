/**
 * Model definition for the Users collection
 */
import mongoose from "mongoose";
import UserSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const User = mongoose.model(Models.User.name, UserSchema);

export default User;
