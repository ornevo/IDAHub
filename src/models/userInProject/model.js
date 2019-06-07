/**
 * Model definition for the Users collection
 */
import mongoose from "mongoose";
import UserInProjectSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const UserInProject = mongoose.model(Models.UserInProject.name, UserInProjectSchema);

export default UserInProject;
