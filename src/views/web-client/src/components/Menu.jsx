import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link, withRouter } from "react-router-dom";
import ResponsiveMenu from 'react-responsive-navbar';
import JWT from "jsonwebtoken";

import { CredContext } from "../shared/Contexts";

import LoginModalContent from "../modals-contents/LoginModalContent";
import SignupModalContent from "../modals-contents/SignupModalContent";
import Modal from './Modal';


class Menu extends Component {
    // We use credentials for the login/logout buttons
    static contextType = CredContext;

    constructor(props) {
        super(props);

        this.state = {
            loginModalOpen: false,
            signupModalOpen: false
        }
    }

    closeModals() {
        this.setState({
            loginModalOpen: false,
            signupModalOpen: false
         });
    }

    // Called on either login or signup
    onNewAuthToken(newToken) {
        this.closeModals();

        // Upon user login/signup, redirect to the user's profile page, upon logout redirect to /
        if(!newToken)
            this.props.history.push("/");
        else {
            const decodedToken = JWT.decode(newToken);
            this.props.history.push('/profile/' + decodedToken.id + "/" + decodedToken.username);
        }

        // Propogate up, to set in context
        this.props.setAuthToken(newToken);   
    }

    render() {
        // Either login/signup buttons, or a logout message
        const authField = this.context ? (
            <Link className="Menu-item" to="#" onClick={() => { this.onNewAuthToken(false); }}>Sign out</Link>
        ) : (
            <span>
                <Link className="Menu-item" to="#" onClick={_ => this.setState({loginModalOpen: true})}>
                    Login
                </Link>
                <Link className="Menu-item" to="#" onClick={_ => this.setState({signupModalOpen: true})}>
                    Signup
                </Link>
            </span>
        );

        return (
            <span>
                {/* First render modals, then menu */}
                <Modal isOpen={this.state.loginModalOpen} onClose={_ => this.closeModals()}>
                    <LoginModalContent onLogin={this.onNewAuthToken.bind(this)}/>
                </Modal>

                <Modal isOpen={this.state.signupModalOpen} onClose={_ => this.closeModals()}>
                    <SignupModalContent onSignup={this.onNewAuthToken.bind(this)}/>
                </Modal>

                <ResponsiveMenu
                    menuOpenButton={<div >O</div>}
                    menuCloseButton={<div >X</div>}
                    changeMenuOn="500px"
                    largeMenuClassName="large-menu-classname"
                    smallMenuClassName="small-menu-classname"
                    menu={
                        <div className="Menu-container">
                            { authField }
                            {
                                // Login-dependent links
                                this.context && (
                                    <span>
                                        <Link to="/new-project" className="Menu-item">New Project</Link>
                                    </span>
                                )
                            }
                        </div>
                    }
                />
            </span>
        );
    }
}


Menu.propTypes = {
    // Gets passed the new auth token to be used
    setAuthToken: PropTypes.func.isRequired
}


export default withRouter(Menu);