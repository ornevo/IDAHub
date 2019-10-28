/* Don't ask me whats going on in here. I assume no one will ever read or maintain this code. I deeply apologize if this is not the case. */
import React from 'react';
import PropTypes from "prop-types"
import Button from '@material-ui/core/Button';
import CssBaseline from '@material-ui/core/CssBaseline';
import TextField from '@material-ui/core/TextField';
import Typography from '@material-ui/core/Typography';
import { withStyles } from '@material-ui/core/styles';
import Container from '@material-ui/core/Container';
import Loader from "../components/Loader";
import { FormsMuiStyle } from "../shared/Constants"


class LoginForm extends React.Component {
    constructor(props) {
        super(props);
        this.classes = props.classes;
    }

    onSubmit(e) {
        e.preventDefault();

        const username = e.target.username.value;
        const password = e.target.password.value;

        this.props.onSubmit({ username, password });
        
        return false;
    }

    render() {
        return (
            <Container component="main" maxWidth="xs">
                <CssBaseline />
                <div className={this.classes.paper}>
                    <Typography component="h1" variant="h5">
                    Sign in
                    </Typography>
                    <form className={this.classes.form} onSubmit={this.onSubmit.bind(this)} noValidate>
                    <TextField
                        variant="outlined"
                        margin="normal"
                        required
                        fullWidth
                        id="username"
                        label="Username"
                        name="username"
                        autoFocus
                    />
                    <TextField
                        variant="outlined"
                        margin="normal"
                        required
                        fullWidth
                        name="password"
                        label="Password"
                        type="password"
                        id="password"
                        autoComplete="current-password"
                    />
                    <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        color="primary"
                        className={this.classes.submit}
                    >
                        Sign In
                    </Button>
                    </form>
                    { this.props.isLoading && <Loader /> }
                </div>
            </Container>
        );
    }
}


LoginForm.propTypes = {
    onSubmit: PropTypes.func.isRequired,
    isLoading: PropTypes.bool
};

LoginForm.defaultProps = {
    onSubmit: () => {},
    isLoading: false
}


export default withStyles(FormsMuiStyle)(LoginForm);