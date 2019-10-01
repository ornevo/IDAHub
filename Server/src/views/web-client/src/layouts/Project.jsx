import React from 'react';
import { NotificationManager } from "react-notifications";
import { Types } from "mongoose";

import Page from '../components/Page';
import NewProjectForm from "../forms/NewProjectForm";
import { getProject, getProjectStatistics } from "../shared/API";
import { CredContext } from "../shared/Contexts";
import { Typography } from '@material-ui/core';
import Loader from '../components/Loader';
import UserChip from '../components/UserChip';
import CountUp from 'react-countup';


class Project extends React.Component {
    static contextType = CredContext;

    constructor(props) {
        super(props);

        this.state = {
            project: null,
            statistics: null,
            isAuthorized: true,
            currentContext: this.context
        }
    }

    fetchStatistics() {
        const toFetchId = this.props.match.params.projectId;

        getProjectStatistics(toFetchId, this.context)
            .then(statistics => {
                if(!this.state.statistics || this.state.project.id !== toFetchId)
                    this.setState({ statistics })
            })
            .catch(err => {
                if(err.statusCode == 401)
                    this.setState({isAuthorized: false});
                else
                    NotificationManager.error(err.body);
            })
    }

    // Gets the project from the server and stores it in the state
    fetchProject() {
        const toFetchId = this.props.match.params.projectId;

        getProject(toFetchId, this.context)
            .then(projectHeader => {
                if(!this.state.project || this.state.project.id !== toFetchId)
                    this.setState({project: projectHeader});
            })
            .catch(err => {
                if(err.statusCode == 401)
                    this.setState({isAuthorized: false});
                else
                    NotificationManager.error(err.body);
            });
    }

    fetchAll() {
        this.fetchProject();
        this.fetchStatistics();
    }

    // Check for loggedin/logout changes for re-render
    componentDidUpdate() {
        if(this.state.currentContext === this.context)
            return;
        
        // If here, user logged in / logged out. We need to update projects.
        // If changed user status, reset projects and re-fetch them when reset is done
        this.setState({
            currentContext: this.context,
            project: null,
            isAuthorized: true
        }, () => this.fetchAll());
    }

    // For loading projects and statistics
    componentDidMount() {
        if(this.state.project && this.state.project.id === this.props.match.params.projectId)
            return;

        this.fetchAll();
    }

    // Creates a DOM element representing the statistic 
    createStatisticBlock(statName, statValue) {
        return (
            <div className="ProjectContainer-statistics-block">
                <Typography variant="h4">{statName}</Typography>
                <CountUp end={statValue} />
            </div>
        )
    }

    render() {
        let pageContent = "";

        // To get attributes from it without getting exceptions if null
        const softenedProject = (this.state.project || {});

        if(!this.state.isAuthorized)
            pageContent = (
                <center>
                    <Typography variant="h2">
                        Unauthorized to view project
                    </Typography>
                </center>
            );
        else if(!this.state.project || !this.state.statistics)
            pageContent = <Loader />
        else {
            // If here, we should display project page
            pageContent = (
                <div className="ProjectContainer">
                    {/* Contributors */}
                    <div className="ProjectContainer-contributors-container">
                        <Typography variant="h4">Contributors</Typography>
                        <Typography variant="h6">Online: {this.state.statistics.onlineCount}</Typography>
                        {
                            this.state.project.contributors.map(user => {
                                return (
                                    <span key={user.id} className="ProjectContainer-contributor">
                                        <UserChip 
                                            id={user.id}
                                            username={user.username}
                                            isPrimary={user.id == this.state.project.owner}
                                            clickable={true} />
                                    </span>
                                );
                            })
                        }
                    </div>
                    
                    {/* Description */}
                    <Typography variant="h4" style={{marginBottom: "10px"}}>Description</Typography>
                    <Typography variant="body2">{softenedProject.description}</Typography>

                    {/* Statistics */}
                    { this.createStatisticBlock("Number of Modifications", this.state.statistics.modifications) }
                    <div className="ProjectContainer-small-statistics">
                        { this.createStatisticBlock("Functions", this.state.statistics.functions) }
                        { this.createStatisticBlock("Variables", this.state.statistics.variables) }
                        { this.createStatisticBlock("Comments", this.state.statistics.comments) }
                        { this.createStatisticBlock("Labels", this.state.statistics.labels) }
                    </div>
                </div>
            )
        }

        return (
            <Page title={softenedProject.name || "Invalid"}>
                { pageContent }
            </Page>
        )
    }
}


export default Project;