import React from 'react';
import { Redirect } from "react-router-dom";
import { Types } from "mongoose";
import { NotificationManager } from "react-notifications";
import { Typography } from '@material-ui/core';
import JWT from 'jsonwebtoken';

import { SentRequestsContext, PendingRequestsContext } from "../shared/Contexts";
import Page from '../components/Page';
import { CredContext } from "../shared/Contexts";
import { getUserProjects } from "../shared/API";
import Loader from "../components/Loader";
import ProjectsList from '../components/ProjectsList';
import NotificationSection from "../components/NotificationSection";


export default class ProfileLayout extends React.Component {
    static contextType = CredContext;

    constructor(props) {
        super(props);

        this.state = {
            projects: [],
            loadedProjects: false,
            isValidUser: Types.ObjectId.isValid(props.match.params.userId) && props.match.params.username !== "",
            username: props.match.params.username,
            userId: props.match.params.userId,
            // To recognize user-login/logout
            currentContext: this.context || false
        }
    }

    // Fetches the projects and puts them in the state
    fetchProjects() {
        getUserProjects(this.state.userId, this.context)
            .then(projects => {
                if(!this.state.loadedProjects)
                    this.setState({projects, loadedProjects: true})
            }).catch(err => {
                NotificationManager.error("Failed to fetch user's projects: " + err);
                this.setState({ isValidUser: false })
            });
    }

    // Check for loggedin/logout changes for re-render
    componentDidUpdate() {
        if(this.state.currentContext === this.context)
            return;
        
        // If here, user logged in / logged out. We need to update projects.
        // If changed user status, reset projects and re-fetch them when reset is done
        this.setState({
            currentContext: this.context,
            loadedProjects: false,
            projects: []
        }, () => this.fetchProjects());
    }

    // For loading projects
    componentDidMount() {
        if(this.state.loadedProjects)
            return;

        if(!this.state.isValidUser) {
            console.log("ProfileLayout: Redirecting back to prvious page, passed user invalid: ", this.props.match.params);
            return;
        }
         
        this.fetchProjects();
    }

    isViewingSelfProfile() {
        if(!this.context)
            return false;

        const decodedToken = JWT.decode(this.context);
        
        if(!decodedToken)
            return false;

        return decodedToken.id === this.state.userId;
    }

    render() {
        // If no id, route back
        if(!this.state.isValidUser)
            return <Redirect to="/" />;

        let ownedProjects = [], contributingProjects = [];

        if(this.state.loadedProjects) {
            // All projects where the profile owner is the project owner
            ownedProjects = this.state.projects.filter(proj => proj.owner === this.state.userId);
            // All the project in which profile owner is in the contributors list.
            contributingProjects = this.state.projects.filter(proj => (
                (proj.owner !== this.state.userId) && proj.contributors.find(contr => contr.id === this.state.userId)
            ));

            // Make sure they compliment each other
            if(ownedProjects.length + contributingProjects.length !== this.state.projects.length)
                console.log("Something weird in the user owner's projects: Some are either owned by him nor he is contributing to them. Please check.");
        }

        const isViewingSelf = this.isViewingSelfProfile();

        return (
            <Page title={this.state.username + "'s Profile"}>
                <div className={isViewingSelf ? "SelfProfileContainer" : ""}>
                    {
                        isViewingSelf && (
                            <SentRequestsContext.Consumer>
                                { sentRequests =>
                                    <PendingRequestsContext.Consumer>
                                        { pendingRequests =>
                                            <NotificationSection 
                                                sentRequests={sentRequests}
                                                pendingRequests={pendingRequests}
                                                authToken={this.context}
                                            />
                                        }
                                    </PendingRequestsContext.Consumer>
                                }
                            </SentRequestsContext.Consumer>
                        )                     
                    }

                    <Typography variant="h4" style={{textAlign: 'center'}}>Owned Projects</Typography>
                    {this.state.loadedProjects ?
                        <ProjectsList projects={ownedProjects} />
                        : <Loader />}

                    <br />

                    <Typography variant="h4" style={{textAlign: 'center'}}>Contributor Projects</Typography>
                    {this.state.loadedProjects ?
                        <ProjectsList projects={contributingProjects} />
                        : <Loader />}

                </div>
            </Page>
        );
    }
}
