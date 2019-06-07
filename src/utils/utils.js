import { Protocol } from "./constants";


const createUserDetails = (username, id) => ({ username, id })

const sendJSONResponse = (res, body, isSuccess = true) => {
    res.status(isSuccess ? 200 : Protocol.Status.FailureStatusCode);
    console.log(body);
    
    res.json({
        status: isSuccess ? Protocol.Status.Success : Protocol.Status.Failure,
        body: body 
    });
}


export { createUserDetails, sendJSONResponse };