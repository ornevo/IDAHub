/* Don't ask me whats going on in here. I assume no one will ever read or maintain this code. I deeply apologize if this is not the case. */
import React from 'react';
import PropTypes from 'prop-types';
import LoginForm from "../forms/LoginForm";
import * as HttpStatus from 'http-status-codes'
import { NotificationManager } from "react-notifications";

import 'react-notifications/lib/notifications.css';

import { login } from "../shared/API";
import StatelessFormAPIHandler from "./StatelessFormAPIHandler";


class LoginModalContent extends React.Component {
	validateForm(formData) {
		if (!formData.username || !formData.password) {
			NotificationManager.error("All fields must be filled");
			return false;
		}
		return true;
	}

	onSuccess(body) {
		if (!body || !body.token) {
			NotificationManager.error("Failed extracting auth token.");
			return;
		}

		const token = body.token;
		NotificationManager.success("Success. You are now logged in.");

		this.props.onLogin(token);
	}

	onError(statusCode, body) {
		if (statusCode === HttpStatus.UNAUTHORIZED)
			NotificationManager.error("Failed to authenticate: " + body);
		else
			NotificationManager.error("ERROR: " + body);
	}

	render() {
		return (
			<StatelessFormAPIHandler formToRender={LoginForm} apiFunc={login}
				onError={this.onError.bind(this)} onSuccess={this.onSuccess.bind(this)}
				validator={this.validateForm} />
		);
	}
}


LoginModalContent.propTypes = {
	// This function will receive the token once authenticated.
	onLogin: PropTypes.func.isRequired
}


export default LoginModalContent;