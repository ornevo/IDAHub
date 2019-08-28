/* Don't ask me whats going on in here. I assume no one will ever read or maintain this code. I deeply apologize if this is not the case. */
import React from 'react';
import PropTypes from 'prop-types';
import SignupForm from "../stateless-forms/SignupForm";
import * as HttpStatus from 'http-status-codes'
import { NotificationManager } from "react-notifications";

import 'react-notifications/lib/notifications.css';

import { safeget } from "../shared/Utils";
import { signup, login } from "../shared/API";
import StatelessFormAPIHandler from "./StatelessFormAPIHandler";


class SignupModalContent extends React.Component {
	validateForm(formData) {
		if (!formData.username || !formData.password || !formData.email) {
			NotificationManager.error("All fields must be filled");
			return false;
		}
		return true;
	}

	onSuccess(body) {
		if (!body) {
            NotificationManager.error("Response invalid.");
            return;
        }

        // Get created user details
        const username = body.username;
        // Even though not returned in the original response, added to the body by the api signup function
        const password = body.password;
        
        // After successful signup, login
        login({username, password})
            .then(respBody => {
                NotificationManager.success("Success. Welcome!");
        		this.props.onSignup(respBody.token);
            })
            .catch(k => {
                NotificationManager.error("Signup succeeded, but something went wrong logging in. Please try logging in.");
            });
	}

	onError(statusCode, body) {
		if (statusCode == HttpStatus.UNAUTHORIZED)
			NotificationManager.error("Failed to sign up: " + body);
		else
			NotificationManager.error("ERROR: " + body);
	}

	render() {
		return (
			<StatelessFormAPIHandler formToRender={SignupForm} apiFunc={signup}
				onError={this.onError.bind(this)} onSuccess={this.onSuccess.bind(this)}
				validator={this.validateForm} />
		);
	}
}


SignupModalContent.propTypes = {
	// This function will receive the token once authenticated.
	onSignup: PropTypes.func.isRequired
}


export default SignupModalContent;