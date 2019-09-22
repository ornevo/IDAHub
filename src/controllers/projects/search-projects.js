// Handling path /api/projecs?query=<query>&page=<pagenum>

import escapeStringRegexp from 'escape-string-regexp';
import { defaultParamToMiddleware, validateAuthToken } from "../middleware";
import { getProjectHeaders } from "../../utils/dbhelpers"
import { Project } from "../../models/index";
import { sendJSONResponse, createProjectHeader, isAuthorizedToViewProject } from "../../utils/utils";
import { ResultsPageSize } from "../../utils/constants";
import { query } from 'express-validator/check';


// Some input controll validators
const validators = [
    validateAuthToken(false),
    defaultParamToMiddleware('page', 'query', 1),
    query("query").isAlphanumeric().isLength({ max: 50 }),
    query("page").isNumeric()
]

// Handler
const handler = (req, res) => {
    const searchedQuery = escapeStringRegexp(String(req.query.query || ""));
    const pagenum = req.query.page < 1 ? 1 : req.query.page;
    
    // Check out paginationResult's properties in mongoose-pagination's docs
    Project.paginate(
        { $or: [ // query
            { name: { $regex: searchedQuery, $options: "i" } }, 
            { description: { $regex: searchedQuery, $options: "i" } }
        ]},
        { page: pagenum, limit: ResultsPageSize }, // options
        (err, paginationResult) => {
            if(err) {
                sendJSONResponse(res, err, false);
                return;
            }

            // Get the found project's full header, including contributors
            getProjectHeaders(paginationResult.docs.map(proj => proj._id), (err, projectHeaders) => {
                if(err) {
                    sendJSONResponse(res, err, false);
                    return;
                }
                // No reason for the length check, though doesn't hurt.
                if(projectHeaders.length != paginationResult.docs.length) {
                    sendJSONResponse(res, "Internal error.", false);
                    return;
                }

                // Keep only projects we are authenticated to see
                const filteredProjectHeaders = projectHeaders.filter(project => isAuthorizedToViewProject(req.jwt, project));

                const response = {
                    data: filteredProjectHeaders,
                    pagenum: paginationResult.page,
                    numOfPages: paginationResult.pages
                };
                sendJSONResponse(res, response, true);
            })
        }
    );
};


export default { handler, validators };