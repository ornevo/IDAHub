import React from 'react';
import { NotificationManager } from "react-notifications";
import { Typography } from '@material-ui/core';

import Page from '../components/Page';
import { CredContext } from "../shared/Contexts";
import { userSearch } from "../shared/API";
import ProjectsList from '../components/ProjectsList';
import UsersList from '../components/UsersList';
import Loader from "../components/Loader";


class SearchLayout extends React.Component {
    static contextType = CredContext;

    constructor(props) {
        super(props);

        this.query = props.match.params.query || '';

        this.state = {
            foundProjects: [],
            foundUsers: [],
            hasLoadedProjects: false,
            hasLoadedUsers: false,
            currentContext: this.context || false
        }
    }

    // Fetches the projects and puts them in the state
    fetchUserSearchResults() {
        userSearch(this.query)
            .then(users => {
                if(users && users.data && !this.state.hasLoadedUsers)
                    this.setState({foundUsers: users.data, hasLoadedUsers: true})
            }).catch(err => {
                NotificationManager.error("Failed to search for users: " + err);
            });
    }

    fetchProjectSearchResults() {

    }

    // Check for loggedin/logout changes for re-render
    componentDidUpdate() {
        if(this.state.currentContext === this.context)
            return;
        
        // If here, user logged in / logged out. We need to update found projects.
        // If changed user status, reset projects and re-fetch them when reset is done
        // No need to reload users, as result is the same for all users
        this.setState({
            currentContext: this.context,
            hasLoadedProjects: false,
            foundProjects: []
        }, () => this.fetchProjectSearchResults());
    }

    // For loading projects
    componentDidMount() {
        if(!this.state.hasLoadedProjects)
            this.fetchProjectSearchResults();
        
        if(!this.state.hasLoadedUsers)
            this.fetchUserSearchResults();
    }

    render() {
        return (
            <Page title="Search Results">
                <div>
                    {/* Query label */}
                    <Typography variant="h5" className="SearchLayout-query-label">
                        query: "{this.query}".
                    </Typography>

                    <br />

                    {/* Projects search result */}
                    <Typography variant="h4">Projects</Typography>
                    {this.state.hasLoadedProjects ?
                        <ProjectsList projects={this.state.foundProjects} />
                        : <Loader />}

                    <br />

                    {/* Users search result */}
                    <Typography variant="h4">Users</Typography>
                    {this.state.hasLoadedUsers ?
                        <UsersList users={this.state.foundUsers} />
                        : <Loader />}
                </div>
            </Page>            
        )
    }

}


export default SearchLayout;