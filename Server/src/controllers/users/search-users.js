// Handling path /api/users?name=<query>&page=<pagenum>

import escapeStringRegexp from 'escape-string-regexp';
import { defaultParamToMiddleware } from "../middleware";
import { User } from "../../models/index";
import { sendJSONResponse, createUserDetails } from "../../utils/utils";
import { ResultsPageSize } from "../../utils/constants";
import { query } from 'express-validator/check';


// Some input controll validators
const validators = [
    defaultParamToMiddleware('page', 'query', 1),
    query("name").isAlphanumeric().isLength({ max: 50 }),
    query("page").isNumeric()
]

// Handler
const handler = (req, res) => {
    const searchedName = escapeStringRegexp(String(req.query.name || ""));
    const pagenum = req.query.page < 1 ? 1 : req.query.page;
    
    User.paginate(
        { username: { $regex: searchedName, $options: "i" } }, // query
        { page: pagenum, limit: ResultsPageSize }, // options
        (err, paginationResult) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            // Check out paginationResult's properties in mongoose-pagination's docs
            const response = {
                data: paginationResult.docs.map(user => createUserDetails(user.username, user._id)),
                pagenum: paginationResult.page,
                numOfPages: paginationResult.pages
            };
            sendJSONResponse(res, response, true);
        }
    );
};


export default { handler, validators };