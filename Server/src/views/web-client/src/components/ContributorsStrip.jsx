import React from 'react';
import PropTypes from 'prop-types';
import Chip from '@material-ui/core/Chip';
import { Typography } from '@material-ui/core';
import { FaPlus, FaRegClock } from "react-icons/fa";
import JWT from "jsonwebtoken";
import { NotificationManager } from 'react-notifications';

import UserChip from '../components/UserChip';
import AddContributorsModalContent from '../modals-contents/AddContributorsModalContent';
import { SentRequestsContext } from "../shared/Contexts";
import { sendJoinRequest } from "../shared/API";
import Modal from "../components/Modal";


class ContributorStrip extends React.Component {
    static contextType = SentRequestsContext;

    constructor(props) {
        super(props);

        this.state = {
            isPending: false,
            // Since once sending request the sentRequests context will get updated, this component will get remounted quite quickly.
            //  hence we only need to know whether it generally already sent, because of it's short life afterwards.
            // We need this to prevent some prblems, just don't mess with it
            hasSentSentRequest: false,
            isAddingContributorsModalOpen: false
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
        // Decide how to display the "join" button and whether to show adding users option
        let joinButton = "";
        let addButton = "";

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

            if(decodedToken && decodedToken.id === this.props.projectOwner)
                addButton = (
                    <div className="ProjectContainer-chips-container">
                        <Chip
                            className="UserChip UserChip-join"
                            icon={<FaPlus />}
                            label="Add contributor"
                            color="secondary"
                            onClick={() => this.setState({ isAddingContributorsModalOpen: true }) }
                        />
                    </div>
                );
        }

        // Make sure the owner is rendered first in the list
        let newContributors = this.props.contributors;
        const ownerUserObject = newContributors.find(cont => cont.id === this.props.projectOwner);
        if(ownerUserObject)
            newContributors = [ ownerUserObject ].concat(newContributors.filter(cont => cont.id !== this.props.projectOwner))

        return (
            <div className="ProjectContainer-contributors-container">
                {/* The add contributors dialog, if open */}
                <Modal  isOpen={this.state.isAddingContributorsModalOpen}
                        isOnHomepage={false}
                        onClose={() => this.setState({ isAddingContributorsModalOpen: false })}>
                    <AddContributorsModalContent
                        onAdded={this.props.reloadProject}
                        jwtToken={this.props.authToken}
                        projectId={this.props.projectId}
                    />
                </Modal>

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
                { addButton }
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
