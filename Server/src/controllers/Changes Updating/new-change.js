// Handling path /api/projects/:projectId/push

import { param ,body} from "express-validator/check";
import { Modification} from "../../models/index";
import { getProjectHeaders } from "../../utils/dbhelpers";
import { validateProjectId, validateAuthToken } from "../middleware";
import { Project } from "../../models/index";
import { User } from "../../models/index";
import { UserInProject } from "../../models/index";
import { sendJSONResponse, createUserDetails, createProjectHeader } from "../../utils/utils";

// Some input controll validators
const validators = [
     // check the project id
       validateProjectId(),
     // check the authentication
     validateAuthToken(),
     body("event-id").exists(),
     body("event-id").isNumeric()
    // body( "linear-address").isNumeric(),
     //body("value").isString(),
    // body("label-type").isString(),
    // body("comment-type").isString(),
    // body( "offset").isNumeric(),
    // body("variableType").isString(),
    // body("name").isString(),
    // body("id").isString()
]

// Handler, the route function
const handler = (req, res) => {
    let newModification=new Modification();
    var mongoose = require('mongoose');
    newModification.projectId = mongoose.Types.ObjectId(req.params['projectId']);
    const a=req.jwt;
    newModification.userId = a.id;
    newModification.timestamp = (Math.floor(new Date().getTime()/1000.0)).toString();
    newModification.eventId = req.body["event-id"];



    //check the rest input
    if(!((req.body['linear-address'] && typeof req.body["linear-address"]=="number") || req.body['linear-address']==false)){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body['linear-address'])
            newModification.linearAddress = req.body["linear-address"];
        else
            newModification.linearAddress = null;
    }


    if(!((req.body.hasOwnProperty('value') && typeof req.body.value=="string") || req.body.hasOwnProperty('value')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('value') )
            newModification.value = req.body.value;
        else
            newModification.value = null;
    }
    

    if(!(   (req.body.hasOwnProperty('label-type') && typeof req.body["label-type"] =="string") || req.body.hasOwnProperty('label-type')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('label-type') )
            newModification.labelType = req.body["label-type"];
        else
            newModification.labelType = null;
    }


    if(!(   (req.body.hasOwnProperty('comment-type') && typeof req.body["comment-type"]=="string") || req.body.hasOwnProperty('comment-type')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('comment-type') )
            newModification.commentType = req.body["comment-type"];
        else
            newModification.commentType = null;
    }
    

    if(!(   (req.body.hasOwnProperty('offset') && typeof req.body.offset=="number") || req.body.hasOwnProperty('offset')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('offset') )
            newModification.offset = req.body.offset;
        else
            newModification.offset = null;
    }


    if(!(   (req.body.hasOwnProperty('variable-type') && typeof req.body["variable-type"]=="string") || req.body.hasOwnProperty('variable-type')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('variable-type') )
            newModification.variableType = req.body["variable-type"];
        else
            newModification.variableType = null;
    }


    if(!(   (req.body.hasOwnProperty('name') && typeof req.body.name=="string") || req.body.hasOwnProperty('name')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('name') )
            newModification.name = req.body.name;
        else
            newModification.name = null;
    }


    if(!(   (req.body.hasOwnProperty('id') && typeof req.body.id=="string") || req.body.hasOwnProperty('id')==false   )   ){
        sendJSONResponse(res, "inputError", false);
        return;
    }
    else{
        if(req.body.hasOwnProperty('id') )
            newModification.id = req.body.id;
        else
            newModification.id = null;
    }

    


    // check if the user belongs to the project.
    UserInProject.find({ userId: newModification.userId }, (err, foundDocs) => {
        if(err) {
            sendJSONResponse(res, "error", false);
            return;
        }
    
        const searchedProjectIds = foundDocs.map(d => d.projectId);
        for(var v=0;v<searchedProjectIds.length;v++){
            var vv=searchedProjectIds[v].toString();
            var p=newModification.projectId.toString();
            if(vv==p)  
                flag=true;
        }
         
        if(!flag){
            sendJSONResponse(res, "error", false);
            return;
        }


   
    //Add Modification
    newModification.save((err, savedModification) => {
        if(err) {
            sendJSONResponse(res, "error", false);
            return;
        }
        sendJSONResponse(res, "OK", true);
    })
    });
};
export default { validators, handler };