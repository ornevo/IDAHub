// This component does not render, it simply pulls the server
import React from 'react';
import PropTypes from 'prop-types';
import JWT from 'jsonwebtoken';
import { JOIN_REQUESTS_UPDATE_INTERVAL } from "../shared/Constants";

import { getSentRequests } from "../shared/API";


class Puller extends React.Component {
    componentDidMount() {
        this.updateSentRequests();
    }

    // Checking by doing a shallow comparison of all objects
    areDifferent(current, fetched) {
        if(current.length !== fetched.length)
            return true;
        // If same length, check if all items are the same
        for (let i = 0; i < current.length; i++) {
            const curr = current[i];
            const currFetched = fetched.find(currFetched => currFetched.id === curr.id);
            
            if(!currFetched || typeof currFetched !== typeof {})
                return true;

            // Compare the objects' fields
            if(Object.keys(curr).length !== Object.keys(currFetched).length)
                return true;
            
            // For each key, compare values
            const keys = Object.keys(curr);
            for (let j = 0; j < keys.length; j++) {
                const k = keys[j];
                if(curr[k] !== currFetched[k])
                    return true; 
            }
        }

        return false;
    }

    // This sends a request to the server to refresh the list of requests
    updateSentRequests() {
        const recall = () => setTimeout(this.updateSentRequests.bind(this), JOIN_REQUESTS_UPDATE_INTERVAL);;

        if(!this.props.authToken) {
            recall();
            return;
        }

        const userId = (JWT.decode(this.props.authToken) || {}).id;

        getSentRequests(userId, this.props.authToken)
            .then(sentRequests => {
                // Check if changed
                if(this.areDifferent(this.props.currentSentRequestsList, sentRequests))
                    this.props.updateSentRequestsList(sentRequests);
            }).finally(() => recall());
    }

    render() {
        return "";
    }
}

Puller.propTypes = {
    authToken: PropTypes.string.isRequired,
    updateSentRequestsList: PropTypes.func.isRequired,
    currentSentRequestsList: PropTypes.array.isRequired
}

export default Puller;