/* Don't ask me whats going on in here. I assume no one will ever read or maintain this code. I deeply apologize if this is not the case. */
import React from 'react';
import PropTypes from 'prop-types';
import { NotificationManager } from "react-notifications";

import 'react-notifications/lib/notifications.css';

import AddContributorsForm from "../forms/AddContributorsForm";
import { addContributor } from "../shared/API";
import StatelessFormAPIHandler from "./StatelessFormAPIHandler";


class AddContributorsModalContent extends React.Component {
	validateForm(formData) {
		if (typeof formData !== typeof [] || formData.length === 0 ||
				formData.find(v => !v) || formData.find(v => !v.username)) {
			NotificationManager.error("Invalid value submitted");
			return false;
		}
		return true;
	}

	onSuccess(respBody) {
		if (!respBody) {
            NotificationManager.error("Response invalid.");
            return;
		}
		
		NotificationManager.success("Success adding users.");
		this.props.onAdded(respBody.token);
	}

	onError(statusCode, body) {
		NotificationManager.error("ERROR (" + statusCode.toString() + "): " + body);
	}

	// We need a wrapper because we do many calls
	apiFuncWrapper(usersToAdd) {
		// Add all users, each one seperatly
		const allPromises = usersToAdd.map(user => addContributor(this.props.projectId, user.id, this.props.jwtToken));
		return Promise.all(allPromises).then(allResponses => {
			// If all successfull, just return the first
			if(!allResponses || allResponses.length === 0)
				return null;
			return allResponses[0]; 
		});
	}

	render() {
		return (
			<StatelessFormAPIHandler formToRender={AddContributorsForm} apiFunc={this.apiFuncWrapper.bind(this)}
				onError={this.onError.bind(this)} onSuccess={this.onSuccess.bind(this)}
				validator={this.validateForm} />
		);
	}
}


AddContributorsModalContent.propTypes = {
	// This function will receive the token once authenticated.
	onAdded: PropTypes.func.isRequired,
	jwtToken: PropTypes.string.isRequired,
	projectId: PropTypes.string.isRequired
}


export default AddContributorsModalContent;