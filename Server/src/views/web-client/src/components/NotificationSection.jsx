import React from 'react';
import { Link } from 'react-router-dom';
import PropTypes from 'prop-types';
import { Typography } from '@material-ui/core';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import IconButton from '@material-ui/core/IconButton';
import { FaCheckCircle, FaTimesCircle, FaStream } from 'react-icons/fa';

import UserChip from './UserChip';
import { updateJoinRequestState } from "../shared/API";
import { NotificationManager } from 'react-notifications';


class NotificationSection extends React.Component {
    wrappedUpdateJoinRequestState(...params) {
        this.props.pullerUpdateAllFunc();
        return updateJoinRequestState(...params);
    }

    // Since here is where the user sees the notificatoins, this is where we update the server they have been seen
    componentDidMount() {
        // Notify seen approved requests
        this.props.sentRequests.forEach(req => {
            if(req.approved && !req.seenByRequester)
                this.wrappedUpdateJoinRequestState(req.id, this.props.authToken, { approveSeenByRequester: true })
                    .catch(() => undefined);
        });

        // Notify seen join requests
        this.props.pendingRequests.forEach(req => {
            if(!req.readByOwner)
                this.wrappedUpdateJoinRequestState(req.id, this.props.authToken, { readByOwner: true })
                    .catch(() => undefined);
        })
    }

    onRequestApprove(request) {
        this.wrappedUpdateJoinRequestState(request.id, this.props.authToken, { readByOwner: true, approved: true })
            .then(() => NotificationManager.success("Approved request"))
            .catch(err => NotificationManager.error(err.body || err.toString()));
    }

    onRequestDismiss(request) {
        this.wrappedUpdateJoinRequestState(request.id, this.props.authToken, { readByOwner: true, dismissed: true })
            .then(() => NotificationManager.success("Dismissed request"))
            .catch(err => NotificationManager.error(err.body || err.toString()));
    }

    onApproveDismiss(sentRequest) {
        this.wrappedUpdateJoinRequestState(sentRequest.id, this.props.authToken, { approveReadByRequester: true })
            .catch(err => NotificationManager.error(err.body || err.toString()));
    }

    formatRequestNotif(joinRequest) {
        if(!joinRequest.requester)
            console.log(joinRequest);
        
        return (
            <ListItem key={joinRequest.id} dense button className="RequestNotif-row">
                {/* Approve button */}
                <div className="IconButtonContainer">
                    <IconButton onClick={() => this.onRequestApprove(joinRequest)}>
                        <FaCheckCircle color="green" />
                    </IconButton>
                </div>
                
                {/* Main content */}
                <div className="RequestNotif-container">
                    <UserChip 
                        username={joinRequest.requester.username}
                        id={joinRequest.requester.id}
                        clickable={true}
                        isPrimary={true}
                        className="RequestNotif-chip"
                        />

                    <Link to={"/project/" + joinRequest.project.id}>
                        <Typography variant="subtitle2">Asks to join project</Typography>
                        <Typography variant="subtitle1">{joinRequest.project.name}</Typography>
                    </Link>
                </div>

                {/* Dismiss button */}
                <div className="IconButtonContainer">
                    <IconButton onClick={() => this.onRequestDismiss(joinRequest)}>
                        <FaTimesCircle color="#d91616" />
                    </IconButton>
                </div>
            </ListItem>
        )
    }

    formatApprovedNotif(approveNotif) {
        return (
            <ListItem key={approveNotif.id} dense button className="RequestNotif-row RequestNotif-approve-row">
                {/* Mark as seen */}
                <div className="IconButtonContainer">
                    <IconButton onClick={() => this.onApproveDismiss(approveNotif)}>
                        <FaStream />
                    </IconButton>
                </div>
                
                {/* Main content */}
                <Link to={"/project/" + approveNotif.projectId} className="RequestNotif-container">
                    <Typography variant="subtitle2">Your request to join project</Typography>
                    <Typography variant="subtitle1">{approveNotif.projectName}</Typography>
                    <Typography variant="subtitle2">has been approved!</Typography>
                </Link>
            </ListItem>
        )
    }

    render() {
        if(!this.props.authToken)
            return "";
        
        return (
            <div className="NotificationSection-container">
                <Typography variant="h4">Notifications</Typography>

                <hr />

                <Typography variant="h5">Approved Requests</Typography>
                <List>
                    { this.props.sentRequests.filter(s => s.approved).map(this.formatApprovedNotif.bind(this)) }
                </List>

                <Typography variant="h5">Join Requests</Typography>
                <List>
                    { this.props.pendingRequests.map(this.formatRequestNotif.bind(this)) }
                </List>
            </div>
        );
    }
}


NotificationSection.propTypes = {
    authToken: PropTypes.string.isRequired,
    sentRequests: PropTypes.array.isRequired,
    pendingRequests: PropTypes.array.isRequired,
    pullerUpdateAllFunc: PropTypes.func.isRequired
}


export default NotificationSection;