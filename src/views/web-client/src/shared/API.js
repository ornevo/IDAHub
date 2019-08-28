// Contains some api functions
import axios from 'axios';


const URL = "http://localhost";


// Returns a promise 
export const login = (username, password) => {
    return axios.get(URL + "/api/users/token", {params: {username, password}});
}