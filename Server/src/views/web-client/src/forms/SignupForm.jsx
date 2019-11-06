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
import { NotificationManager } from "react-notifications";
import { FormsMuiStyle } from "../shared/Constants";


const MIN_PASS_LENGTH = 8;


class SignupForm extends React.Component {
    constructor(props) {
        super(props);
        this.classes = props.classes;
        this.state = {
            passwordError: "",
            username: '',
            email: '',
            pass: ''
        }
    }

    onSubmit(e) {
        e.preventDefault();

        if(this.state.passwordError) {
            NotificationManager.error("Please choose a strong password");
            return;
        }

        const username = e.target.username.value;
        const password = e.target.password.value;
        const email = e.target.email.value;

        this.props.onSubmit({ username, password, email });
        
        return false;
    }

    onPasswordChange(e) {
        const pass = e.target.value;
        if(!pass)
            return;
        this.setState({pass}, this.validatePassword.bind(this));
    }

    validatePassword() {
        const pass = this.state.pass;
        
        if(pass.length < MIN_PASS_LENGTH)
            this.setState({passwordError: "Password must be more than " + MIN_PASS_LENGTH + " characters."});
        else if(!pass.match(/[a-z]/g))
            this.setState({passwordError: "Password must contain at least one lower-case letter"});
        else if(!pass.match(/[A-Z]/g))
            this.setState({passwordError: "Password must contain at least one upper-case letter"});
        else if(!pass.match(/[0-9]/g))
            this.setState({passwordError: "Password must contain at least one digit"});
        else if(!["!", "@", "#", "$", "%", "^", "&", "*", "+", "."].map(sym => pass.includes(sym)).includes(true))
            this.setState({passwordError: "Password must contain at least one special character"});
        else if(this.state.username && (pass.includes(this.state.username) || this.state.username.includes(pass)))
            this.setState({passwordError: "Password too similar to username."});
        else if(this.state.email && (pass.includes(this.state.email) || this.state.email.includes(pass)))
            this.setState({passwordError: "Password too similar to email."});
        else
            this.setState({passwordError: ""});
    }

    render() {
        return (
            <Container component="main" maxWidth="xs">
                <CssBaseline />
                <div className={this.classes.paper}>
                    <Typography component="h1" variant="h5">
                    Sign up
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
                        onChange={e => this.setState({username: e.target.value}, this.validatePassword.bind(this))}
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
                        onChange={this.onPasswordChange.bind(this)}
                        autoComplete="current-password"
                    />

                    <span style={{color: 'red'}} >
                        {this.state.passwordError}
                    </span>

                    <TextField
                        variant="outlined"
                        margin="normal"
                        required
                        fullWidth
                        name="email"
                        label="email"
                        type="email"
                        id="email"
                        onChange={e => this.setState({email: e.target.value.split("@")[0]}, this.validatePassword.bind(this))}
                        autoComplete="email"
                    />
                    <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        color="primary"
                        className={this.classes.submit}
                    >
                        Sign Up
                    </Button>
                    </form>
                    { this.props.isLoading && <Loader /> }
                </div>
            </Container>
        );
    }
}


SignupForm.propTypes = {
    onSubmit: PropTypes.func.isRequired,
    isLoading: PropTypes.bool
};

SignupForm.defaultProps = {
    onSubmit: () => {},
    isLoading: false
}


export default withStyles(FormsMuiStyle)(SignupForm);