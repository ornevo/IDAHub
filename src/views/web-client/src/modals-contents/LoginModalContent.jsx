/* Don't ask me whats going on in here. I assume no one will ever read or maintain this code. I deeply apologize if this is not the case. */
import React from 'react';
import PropTypes from 'prop-types';
import LoginForm from "../stateless-forms/LoginForm";
import * as HttpStatus from 'http-status-codes'
import { NotificationManager } from "react-notifications";

import 'react-notifications/lib/notifications.css';

import { safeget } from "../shared/Utils"; 
import { login } from "../shared/API";


class LoginModalContent extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      isLoading: false
    }
  }

  onSubmit(data) {
    if(!data.username || !data.password) {
      NotificationManager.error("All fields must be filled");
      return;
    } 

    this.setState({isLoading: true});

    // Try to login 
    login(data.username, data.password)
      .then(resp => {
        const token = safeget(['data', 'body', 'token'], resp);
        if(!token)
          NotificationManager.error("Failed extracting auth token.");

        NotificationManager.success("Success. You are now logged in.");
        
        this.props.onLogin(token);

        this.setState({isLoading: false});
      })
      .catch(error => {
        const errorCode = safeget(['response', 'status'], error) || HttpStatus.UNAUTHORIZED;
        const errorDesc = safeget(['response', 'data', 'body'], error);
        if(errorCode == HttpStatus.UNAUTHORIZED)
            NotificationManager.error("Failed to authenticate: " + errorDesc);
        else
          NotificationManager.error("ERROR: " + errorCode + ": " + error.response.data);

        this.setState({isLoading: false});
      });
  }

  render() {
    return (
      <LoginForm isLoading={this.state.isLoading} onSubmit={this.onSubmit.bind(this)} />
    );
  }
}


LoginModalContent.propTypes = {
  // This function will receive the token once authenticated.
  onLogin: PropTypes.func.isRequired
}


export default LoginModalContent;