import React from 'react';
import { Link } from 'react-router-dom';
import PropTypes from 'prop-types';
import { Typography } from '@material-ui/core';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import IconButton from '@material-ui/core/IconButton';
import { FaCheckCircle, FaTimesCircle, FaStream } from 'react-icons/fa';

import UserChip from './UserChip';
import { SentRequestsContext, PendingRequestsContext } from "../shared/Contexts";


class NotificationSection extends React.Component {
    genNotificationClickHandler(notificationObject) {
        return function() {
            console.log("Clicked: ", notificationObject);
        }
    }

    onRequestApprove(request) {
        console.log("Approved " + request.id);
    }

    onRequestDismiss(request) {
        console.log("Dismissed " + request.id);
    }

    onApproveDismiss(sentRequest) {
        console.log("Marked as read approval " + sentRequest.id);
    }

    formatRequestNotif(joinRequest) {
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
                    <SentRequestsContext.Consumer>
                        { sentRequests => sentRequests.filter(s => s.approved).map(this.formatApprovedNotif.bind(this)) }
                    </SentRequestsContext.Consumer>
                </List>

                <Typography variant="h5">Join Requests</Typography>
                <List>
                    <PendingRequestsContext.Consumer>
                        { pendingRequests => pendingRequests.map(this.formatRequestNotif.bind(this)) }
                    </PendingRequestsContext.Consumer>
                </List>
            </div>
        );
    }
}


NotificationSection.propTypes = {
    authToken: PropTypes.string.isRequired
}


export default NotificationSection;