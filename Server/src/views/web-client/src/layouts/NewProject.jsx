import React from 'react';
import { NotificationManager } from "react-notifications";
import { Types } from "mongoose";
import { Redirect } from "react-router-dom";

import Page from '../components/Page';
import NewProjectForm from "../forms/NewProjectForm";
import { newProject } from "../shared/API";
import { CredContext } from "../shared/Contexts";


export default class NewProjectLayout extends React.Component {
    static contextType = CredContext;

    constructor(props) {
        super(props);
        this.state = { createdProjectId: '' };
    }

    validate(values) {
        let { projectName, projectDescription, isPrivate, contributers, reversedFileHash } = values;
        let authApiKey = this.context;

        if(!authApiKey) {
            NotificationManager.error("Please sign in first");
            return false;
        }

        projectName = projectName.trim();
        if(!projectName) {
            NotificationManager.error("Please provide a project name");
            return false;
        }

        if(projectDescription.length > 10000) {
            NotificationManager.error("Project description too long, max 10000 characters, though got " + projectDescription.length);
            return false;
        }

        if(typeof isPrivate !== 'boolean') {
            NotificationManager.error("Private/Public value corrupted, something went wrong.");
            return false;
        }

        if(contributers === undefined ||
                contributers.find === undefined ||
                contributers.find(v => (!v.id || !v.username || !Types.ObjectId.isValid(v.id)))) {
            NotificationManager.error("Contributers corrupted, something went wrong.");
            return false;
        }

        if(!reversedFileHash || !reversedFileHash.match(/\b[A-Fa-f0-9]{64}\b/)) {
            NotificationManager.error("Reversed file sha256 hash either not supplied or invalid.");
            return false;
        }

        return true;
    }

    onSubmit(values) {
        if(!this.validate(values))
            return;

        let { projectName, projectDescription, isPrivate, contributers, reversedFileHash } = values;
        let authApiKey = this.context;

        newProject(authApiKey, projectName, projectDescription, isPrivate, contributers, reversedFileHash).then(
            newProjectHeader => {
                NotificationManager.success("Project created");
                const projId = newProjectHeader['project-header'].id;
                this.setState({ createdProjectId: projId });
            }
        ).catch(error => NotificationManager.error(error.body));
    }

    render() {
        if(this.state.createdProjectId)
            return <Redirect to={"/project/" + this.state.createdProjectId} />

        return (
            <Page title="New Project">
                <NewProjectForm jwtToken={this.context} onSubmit={this.onSubmit.bind(this)} />
            </Page>
        )
    }
}