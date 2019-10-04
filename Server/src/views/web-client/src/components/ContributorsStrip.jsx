import React from 'react';
import PropTypes from 'prop-types';
import Chip from '@material-ui/core/Chip';
import { Typography } from '@material-ui/core';
import { FaPlus, FaRegClock } from "react-icons/fa";
import JWT from "jsonwebtoken";

import UserChip from '../components/UserChip';
import { SentRequestsContext } from "../shared/Contexts";
import { sendJoinRequest } from "../shared/API";
import { NotificationManager } from 'react-notifications';


class ContributorStrip extends React.Component {
    static contextType = SentRequestsContext;

    constructor(props) {
        super(props);

        this.state = {
            isPending: false,
            // Since once sending request the sentRequests context will get updated, this component will get remounted quite quickly.
            //  hence we only need to know whether it generally already sent, because of it's short life afterwards.
            // We need this to prevent some prblems, just don't mess with it
            hasSentSentRequest: false
        }
    }

    // Called upon context update
    componentDidUpdate() {
        this.updatePendingStatus()
    }
    componentDidMount() {
        this.updatePendingStatus()
    }

    updatePendingStatus() {
        const isCurrentlyPending = this.isOnPendingList();

        if(!this.state.isPending && isCurrentlyPending)
            this.setState({isPending: isCurrentlyPending});

        // If been pending but now not (and we finished sending the request), the request got approved, reload to be up to date
        if(this.state.isPending && !this.state.hasSentSentRequest && !isCurrentlyPending)
            this.props.reloadProject();
    }

    isOnPendingList() {
        if(!this.context)
            return this.state.isPending;

        return this.context.find(req => req.projectId === this.props.projectId) !== undefined;
    }

    onJoinClick() {
        this.setState({hasSentSentRequest: true}, () =>
            sendJoinRequest(this.props.projectId, this.props.authToken)
            .then(_ =>
                this.setState({isPending: true})
            ).catch(err => {
                this.setState({hasSentSentRequest: false})
                NotificationManager.error(err.body);
            })
        )
    }

    render() {
        // Decide how to display the "join" button
        let joinButton = "";
        if(this.props.authToken) {
            
            const decodedToken = JWT.decode(this.props.authToken);
            
            if(decodedToken && !this.props.contributors.find(cont => cont.id === decodedToken.id)) {
                const isDisabled = this.state.hasSentSentRequest || this.state.isPending;
                joinButton = (
                    <Chip
                        className={"UserChip UserChip-join GradientBackground" + (isDisabled ? " UserChip-join-disabled" : "")}
                        color="primary"
                        label={this.state.isPending ? "Request sent" : "Join"}
                        onClick={isDisabled ? null : this.onJoinClick.bind(this)}
                        icon={this.state.isPending ? <FaRegClock /> : <FaPlus />}
                    />
                );
            }
        }

        // Make sure the owner is rendered first in the list
        let newContributors = this.props.contributors;
        const ownerUserObject = newContributors.find(cont => cont.id === this.props.projectOwner);
        if(ownerUserObject)
            newContributors = [ ownerUserObject ].concat(newContributors.filter(cont => cont.id !== this.props.projectOwner))

        return (
            <div className="ProjectContainer-contributors-container">
                <Typography variant="h4">Contributors</Typography>
                <Typography variant="h6">Online: {this.props.onlineCount}</Typography>
                <div className="ProjectContainer-chips-container">
                    { joinButton }
                </div>
                {
                    newContributors.map(user => (
                        <span key={user.id} className="ProjectContainer-contributor">
                            <UserChip 
                                id={user.id}
                                username={user.username}
                                isPrimary={user.id === this.props.projectOwner}
                                clickable={true} />
                        </span>
                    ))
                }
            </div>
        )
    }
}


ContributorStrip.propTypes = {
    onlineCount: PropTypes.number.isRequired,
    projectOwner: PropTypes.string.isRequired,
    projectId: PropTypes.string.isRequired,
    authToken: PropTypes.string,
    contributors: PropTypes.arrayOf(PropTypes.object).isRequired,

    reloadProject: PropTypes.func.isRequired
}


export default ContributorStrip;
