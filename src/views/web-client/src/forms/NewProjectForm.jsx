import React from 'react';
import PropTypes from "prop-types"
import {
    Container, Button, Switch, FormHelperText,
    Typography, FormLabel, TextField
} from '@material-ui/core';
import { withStyles } from '@material-ui/core/styles';

import Loader from "../components/Loader";
import UserSelector from "../components/UserSelector";
import { FormsMuiStyle } from "../shared/Constants"

import createHashCalculatingWorker from "../workers/HashCalculatingWorker";
import { NotificationManager } from 'react-notifications';


class NewProjectForm extends React.Component {
    constructor(props) {
        super(props);

        this.classes = props.classes;
        this.fileReader = null;

        // Since hash calculation may take some time, calculation async in a worker.
        this.hashCalculationWorker = createHashCalculatingWorker(
            this.onHashCalculationFinished.bind(this),
            this.onHashCalculationFailed.bind(this)
        );

        this.state = {
            isPrivate: false,
            fileHash: "",
            contributers: [],
            isCalculatingHash: false
        }
    }

    onHashCalculationFailed(e) {
        this.setState({ fileHash: "", isCalculatingHash: false });
        NotificationManager.error("Failed to calculate hash: " + e.message);
    }

    onHashCalculationFinished(e) {
        const calculatedHash = e.data;        
        // When done, update result and remove loading animation
        this.setState({ fileHash: calculatedHash, isCalculatingHash: false });
    }

    handleReversedFileData(_) {
        const contentAsArrayBuffer = this.fileReader.result;
        if (!contentAsArrayBuffer)
            return;

        const asUintArr = new Uint8Array(contentAsArrayBuffer);
        // Sent to be calculated in a worker. Once finished, will call the callback defined in the constructor
        this.hashCalculationWorker.postMessage(asUintArr);
    }

    onHashChange(e) {
        const newHash = e.target.value.substring(0, 64);
        this.setState({ fileHash: newHash });
    }

    onReversedFileChange(e) {
        if (e.target.files.length === 0)
            return;

        // Since hash calculation may take some time, display loading symbol
        this.setState({isCalculatingHash: true});

        const chosenFile = e.target.files[0];
        this.fileReader = new FileReader();
        this.fileReader.onloadend = this.handleReversedFileData.bind(this);
        this.fileReader.readAsArrayBuffer(chosenFile);
    }

    onUsersSelected(selectedUsers) {
        this.setState({ contributers: selectedUsers });
    }

    onSubmit(e) {
        e.preventDefault();

        const projectName = e.target.projectName.value;
        const projectDescription = e.target.description.value;
        const isPrivate = this.state.isPrivate;
        const contributers = this.state.contributers;
        const reversedFileHash = this.state.fileHash;

        this.props.onSubmit({ projectName, projectDescription, isPrivate, contributers, reversedFileHash });

        return false;
    }

    render() {
        return (
            <Container component="main">
                <form className={this.classes.form + " NewProjectForm"} onSubmit={this.onSubmit.bind(this)} noValidate>
                    <Typography variant="h4">Basic Information</Typography>
                    <div className="NewProjectForm-first-line">
                        {/* The project name */}
                        <TextField
                            required
                            autoFocus
                            variant="outlined"
                            margin="normal"
                            id="projectName"
                            label="Project Name"
                            name="projectName"
                            helperText="Please choose a name for the project"
                            fullWidth
                            autoFocus
                        />
                        {/* public/private control */}
                        <div className="NewProjectForm-switch-container">
                            <div>
                                <FormLabel>Private</FormLabel>
                                <Switch
                                    checked={this.state.isPrivate}
                                    onChange={() => { this.setState({ isPrivate: !this.state.isPrivate }) }}
                                    value="checkedC"
                                />
                                <FormLabel>Public</FormLabel>
                            </div>
                            <FormHelperText style={{ maxWidth: "300px" }}>
                                <b>Public</b> projects are visible to the world, but only editable by approved members.
                                <br />
                                <b>Private</b> projects can only be viewed by selected contributers.
                            </FormHelperText>
                        </div>
                    </div>

                    {/* Description */}
                    <TextField
                        label="Project description"
                        variant="outlined"
                        multiline
                        name="description"
                        rows="4"
                        fullWidth
                        maxLength="10000"
                        helperText="A short description of the reversed file or project"
                    />

                    {/* File selection */}
                    <Typography variant="h4">Reversed file</Typography>
                    <Typography variant="subtitle1">
                        To identify the file, a sha256 hash of the reversed file is used.
                        You could supply the hash yourself or calculate it locally here.
                        The file will not be uploaded and the hash is calculated in the browser.
                    </Typography>

                    <div className="NewProjectForm-hash-inputs-line">
                        <div id="NewProjectForm-automatic-hash-row">
                            <Typography variant="h5">Automatic hash</Typography>
                            <input
                                className={this.classes.input}
                                style={{ display: 'none' }}
                                id="NewProjectForm-raised-button-file"
                                type="file"
                                onChange={this.onReversedFileChange.bind(this)}
                            />
                            <label htmlFor="NewProjectForm-raised-button-file">
                                <Button disabled={this.state.isCalculatingHash} variant="outlined" fullWidth component="div" className={this.classes.button + " MuiFormControl-marginNormal"}>
                                    Choose file
                                </Button>
                            </label>
                            {this.state.isCalculatingHash && <Loader />}
                        </div>
                        <Typography variant="h5" className="NewProjectForm-or-middle-text">OR</Typography>
                        <div>
                            <Typography variant="h5">Supply hash manually</Typography>
                            <TextField
                                required
                                onChange={this.onHashChange.bind(this)}
                                value={this.state.fileHash}
                                variant="outlined"
                                margin="normal"
                                id="fileHash"
                                label="File SHA256 Hash"
                                name="fileHash"
                                helperText="Supply the sha256 hash of the reveresed file."
                                fullWidth
                            />
                        </div>
                    </div>

                    {/* Contributers */}
                    <Typography variant="h4">Contributers</Typography>
                    <Typography variant="subtitle1">Users allowed to make changes to the project.</Typography>
                    <UserSelector onChange={this.onUsersSelected.bind(this)} />

                    <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        color="primary"
                        className={this.classes.submit}
                    >
                        Create
                    </Button>
                </form>
                {this.props.isLoading && <Loader />}
            </Container>
        );
    }
}

NewProjectForm.propTypes = {
    onSubmit: PropTypes.func.isRequired,
    isLoading: PropTypes.bool
};

NewProjectForm.defaultProps = {
    onSubmit: () => { },
    isLoading: false
}

export default withStyles(FormsMuiStyle)(NewProjectForm);