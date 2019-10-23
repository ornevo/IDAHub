import React from 'react';
import PropTypes from "prop-types"
import Button from '@material-ui/core/Button';

import CssBaseline from '@material-ui/core/CssBaseline';
import Typography from '@material-ui/core/Typography';
import { withStyles } from '@material-ui/core/styles';
import Container from '@material-ui/core/Container';

import Loader from "../components/Loader";
import UserSelector from "../components/UserSelector";
import { FormsMuiStyle } from "../shared/Constants"



class AddContributorsForm extends React.Component {
    constructor(props) {
        super(props);
        this.classes = props.classes;
        this.state = {
            chosenUsers: []
        }
    }

    render() {
        return (
            <Container component="main" maxWidth="xs">
                <CssBaseline />

                <div className={this.classes.paper}>
                    <Typography component="h1" variant="h5">
                        Add Contributors
                    </Typography>

                    <Typography variant="subtitle1">
                        Add contributors to the project. Contributor users are able to view, track live changes and sessions, and make changes themselfes in the project.
                    </Typography>

                    {/* Horizonatal seperator */}
                    <div style={{ marginTop: "15px", height: "2px", background: "rgb(2,0,36)" }} ></div>

                    <UserSelector onChange={toAddUsers => this.setState({chosenUsers: toAddUsers})} />

                    <Button
                        type="submit"
                        fullWidth
                        onClick={() => this.props.onSubmit(this.state.chosenUsers)}
                        variant="contained"
                        color="primary"
                        className={this.classes.submit}
                    >
                        Add
                    </Button>

                    { this.props.isLoading && <Loader /> }
                </div>
            </Container>
        )
    }
}


AddContributorsForm.propTypes = {
    onSubmit: PropTypes.func.isRequired,
    isLoading: PropTypes.bool
};

AddContributorsForm.defaultProps = {
    onSubmit: () => {},
    isLoading: false
}


export default withStyles(FormsMuiStyle)(AddContributorsForm);