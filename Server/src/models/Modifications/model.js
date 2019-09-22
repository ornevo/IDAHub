/**
 * Model definition for the Modifications collection
 */
import mongoose from "mongoose";
import ModificationSchema from "./schema";
import { Models } from "../../utils/constants";

// A good place for middleware definitions

const  Modification= mongoose.model(Models.Modification.name, ModificationSchema);

export default Modification;

