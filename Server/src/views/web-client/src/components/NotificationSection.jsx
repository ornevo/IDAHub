import React from 'react';
import { Link } from 'react-router-dom';
import PropTypes from 'prop-types';
import { Typography } from '@material-ui/core';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import IconButton from '@material-ui/core/IconButton';
import { FaCheckCircle, FaTimesCircle } from 'react-icons/fa';
import UserChip from './UserChip';


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
                <Link to={"/project/" + joinRequest.project.id} className="RequestNotif-container">
                    <UserChip 
                        username={joinRequest.requester.username}
                        id={joinRequest.requester.id}
                        clickable={true}
                        isPrimary={true}
                        className="RequestNotif-chip"
                        />

                    <Typography variant="subtitle2">Asks to join project</Typography>

                    <Typography variant="subtitle1">{joinRequest.project.name}</Typography>
                </Link>

                {/* Dismiss button */}
                <div className="IconButtonContainer">
                    <IconButton onClick={() => this.onRequestDismiss(joinRequest)}>
                        <FaTimesCircle color="#d91616" />
                    </IconButton>
                </div>
            </ListItem>
        )
    }

    render() {
        if(!this.props.authToken)
            return "";
        
        const value = 1;
        const exampleNotif = {
            "id": "5d9698e41e058279578ac001",
            "project": {
                "name": "BobRossProj",
                "description": "This is bobross style description",
                "hash": "This is bobross style description",
                "owner": "5d177e45376974165ed10b85",
                "id": "5d96985f1e058279578abfff",
                "public": true,
                "contributors": [
                    {
                        "username": "BobRoss",
                        "id": "5d177e45376974165ed10b85"
                    },
                    {
                        "username": "ornevo",
                        "id": "5cfa7566f5366524280cf2c5"
                    },
                    {
                        "username": "admin",
                        "id": "5cfba1b83175fe6527760a22"
                    }
                ]
            },
            "requester": {
                "username": "admin",
                "id": "5cfba1b83175fe6527760a22"
            },
            "readByOwner": false,
            "approved": false,
            "dismissed": false
        }

        return (
            <div className="NotificationSection-container">
                <Typography variant="h4">Notifications</Typography>
                <List>
                    { this.formatRequestNotif(exampleNotif) }
                    {/* <ListItem key={value} role={undefined} dense button onClick={this.genNotificationClickHandler(value)}>
                        <ListItemIcon>
                        <Checkbox
                            edge="start"
                            checked={false}
                            tabIndex={-1}
                            disableRipple
                            inputProps={{ 'aria-labelledby': labelId }}
                        />
                        </ListItemIcon>
                        <ListItemText id={labelId} primary={`Line item ${value + 1}`} />
                        <ListItemSecondaryAction>
                        <IconButton edge="end" aria-label="comments">
                            <FaStream />
                        </IconButton>
                        </ListItemSecondaryAction>
                    </ListItem> */}
                </List>
            </div>
        );
    }
}


NotificationSection.propTypes = {
    authToken: PropTypes.string.isRequired
}


export default NotificationSection;