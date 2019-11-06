/**
 * Model definition for the Projects collection
 */
import mongoose from "mongoose";
import ProjectSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const Project = mongoose.model(Models.Project.name, ProjectSchema);

export default Project;
