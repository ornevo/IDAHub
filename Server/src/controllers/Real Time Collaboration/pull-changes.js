// Handling path /api/projects/:projectId/push

import { param ,body} from "express-validator/check";
import { Modification} from "../../models/index";
import { getProjectHeaders } from "../../utils/dbhelpers";
import { validateProjectId, validateAuthToken } from "../middleware";
import { Project } from "../../models/index";
import { User } from "../../models/index";
import { UserInProject } from "../../models/index";
import { Session } from "../../models/index";
import { sendJSONResponse, createUserDetails, createProjectHeader } from "../../utils/utils";

// Some input controll validators
const validators = [
// check the project id
       validateProjectId(),
     // check the authentication
     validateAuthToken(),
     body("lastUpdate").isNumeric()
]

// Handler, the route function
const handler = (req, res) => {
    var mongoose = require('mongoose');
    var projId = mongoose.Types.ObjectId(req.params['projectId']);
    var curtimestamp = (Math.floor(new Date().getTime()/1000.0)).toString();
    var lastupdate = req.body.lastUpdate;
    var loggedOn;
    var loggedOff;
    var symbols;


   // Finding the logged-on users, users who have started a session and hav not finished them yet.
    Session.find({endTimestamp:null,projectId:projId}
    ,(err,foundDocs) =>{
        if(err) {
            sendJSONResponse(res, "err", false);
            return;
        }
        
       
        const usersIds = foundDocs.map(d => d.userId);
        User.find({_id:{$in:usersIds}}
            ,(err,docs)=>{
                if(err) {
                    sendJSONResponse(res, "err", false);
                    return;
                }
                loggedOn= docs.map(user => ({ id: user._id, username: user.username}));
                


                //Session.find({ startTimestamp:{$lt : lastupdate},endTimestamp:{ $gt: lastupdate},projectId:projId}
                //,(err,foundDocs) =>{
                //   if(err) {
                //      sendJSONResponse(res, "err", false);
                //    return;
                //}
                   
                UserInProject.find({ projectId:projId,userId:{$nin:usersIds }}, (err, foundDocs2) => {
                    if(err) {
                        sendJSONResponse(res, err, false);
                        return;
                    }
                    //       User.find({_id:{$in:usersIds}}
                    //         ,(err,docs)=>{
                    //           if(err) {
                    //             sendJSONResponse(res, "err", false);
                    //           return;
                    //     }
                    const usersIds = foundDocs2.map(d => d.userId);
                    for(var i=0;i<foundDocs.length;i++)
                        console.log(foundDocs[i]);
                    User.find({_id:{$in:usersIds}}
                        ,(err,docs)=>{
                            if(err) {
                                sendJSONResponse(res, "err", false);
                                return;
                            }
                            loggedOff= docs.map(user => ({ id: user._id, username: user.username}));



                            Modification.find({timestamp:{$gt:lastupdate},projectId:projId}
                    ,(err,foundDocs) =>{
                        if(err) {
                            sendJSONResponse(res, "err", false);
                            return;
                        }                      
                        symbols=foundDocs
                        sendJSONResponse(res, {symbols,loggedOn,loggedOff,curtimestamp} , true);
                    })
                        })
                })

           })
    })
    
};

export default { validators, handler };
