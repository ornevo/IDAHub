import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link, withRouter } from "react-router-dom";
import ResponsiveMenu from 'react-responsive-navbar';
import Container from '@material-ui/core/Container';
import JWT from "jsonwebtoken";

import { CredContext } from "../shared/Contexts";

import LoginModalContent from "../modals-contents/LoginModalContent";
import SignupModalContent from "../modals-contents/SignupModalContent";
import Modal from './Modal';
import Avatar from "../components/Avatar";


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
        /* LOGGED IN INFO */
        const username = this.context ? JWT.decode(this.context).username : "";
        const userId = this.context ? JWT.decode(this.context).id : "";

        /* CLASSES */

        // String, either "homepage" or "regular". Appended to class names for different styling
        const mode = this.props.location.pathname === "/" ? "homepage" : "regular";
        const menuItemsClass = "Menu-item Menu-item-" + mode;
        // The container, main parent of the links
        const containerClass = "Menu-container Menu-container-" + mode + (this.context ? " Menu-container-loggedin" : "");
        // The main div
        const bgClass = "Menu-bg Menu-bg-" + mode;

        /* LINKS DOM */

        // Either login/signup buttons, or a logout links
        const accountLinksWhenLoggedIn = [
            (<Link className={ menuItemsClass } to="#" onClick={() => { this.onNewAuthToken(false); }}>Sign out</Link>),
            (<Link to={"/profile/" + userId + "/" + username}> <Avatar variant="menu" username={ username } /> </Link> )
        ];
        const accountLinksWhenLoggedOut = [
            (<Link className={ menuItemsClass } to="#" onClick={_ => this.setState({loginModalOpen: true})}> Login </Link>),
            (<Link className={ menuItemsClass } to="#" onClick={_ => this.setState({signupModalOpen: true})}> Signup </Link>)
        ]
        const accountLinks = this.context ? accountLinksWhenLoggedIn : accountLinksWhenLoggedOut;

        // other login-dependent links
        const loginDependentLinks = [
            (<Link to="/new-project" className={ menuItemsClass }> New Project </Link>)
        ]
        
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
                        <div className={bgClass}>
                            <Container className={containerClass}>
                                {/* For each login-dependent link, render place holder if shouldn't appear */}
                                { loginDependentLinks.map(link => this.context ? link : <div></div> ) }

                                {/* Empty 1fr space in the middle placeholder */}
                                <div></div>

                                {/* Auth fields */}
                                { accountLinks }
                            </Container>
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