// This component does not render, it simply pulls the server
import React from 'react';
import PropTypes from 'prop-types';
import JWT from 'jsonwebtoken';
import Equal from 'fast-deep-equal';

import { JOIN_REQUESTS_UPDATE_INTERVAL } from "../shared/Constants";
import { getSentRequests, getPendingRequests } from "../shared/API";


class Puller extends React.Component {
    updateAll() {
        this.updateSentRequests();
        this.updatePendingRequests();
    }

    componentDidMount() {
        this.updateAll();
    }

    // This sends a request to the server to refresh the list of pending requests for approval
    updatePendingRequests() {
        const recall = () => setTimeout(this.updatePendingRequests.bind(this), JOIN_REQUESTS_UPDATE_INTERVAL);;

        if(!this.props.authToken) {
            recall();
            return;
        }

        const userId = (JWT.decode(this.props.authToken) || {}).id;

        getPendingRequests(userId, this.props.authToken)
            .then(pendingRequests => {
                // Check if changed
                if(!Equal(this.props.currentPendingRequestsList, pendingRequests))
                    this.props.updatePendingRequestsList(pendingRequests);
            }).finally(() => recall());
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
                if(!Equal(this.props.currentSentRequestsList, sentRequests))
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
    currentSentRequestsList: PropTypes.array.isRequired,

    updatePendingRequestsList: PropTypes.func.isRequired,
    currentPendingRequestsList: PropTypes.array.isRequired
}

export default Puller;