import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link, withRouter } from "react-router-dom";
import ResponsiveMenu from 'react-responsive-navbar';
import Container from '@material-ui/core/Container';
import JWT from "jsonwebtoken";

import { CredContext, SentRequestsContext, PendingRequestsContext } from "../shared/Contexts";

import LoginModalContent from "../modals-contents/LoginModalContent";
import SignupModalContent from "../modals-contents/SignupModalContent";
import Modal from './Modal';
import Avatar from "../components/Avatar";
// import logo from '../res/logo-black.png';
import logoBG from '../res/logo-gradient-start.png';
import logoFG from '../res/logo-gradient-end.png';
import SearchBar from './SearchBar';


class Menu extends Component {
    // We use credentials for the login/logout buttons
    static contextType = CredContext;

    constructor(props) {
        super(props);

        this.state = {
            loginModalOpen: false,
            signupModalOpen: false,
            // To recognize user-login/logout
            currentContext: this.context || false
        }
    }

    // Check for loggedin/logout changes for re-render
    componentDidUpdate() {
        if(this.state.currentContext !== this.context)
            this.setState({currentContext: this.context});
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
        if(!newToken) {
            this.props.history.push("/");
        } else {
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

        // We make the logo change colors by setting the container with a background imag of the logo in color A,
        //  and the image in color B, and "blinking" the opacity of the image, revealing and hiding the background. 
        const homeLogoLink = mode === "homepage" ? "" : (
            <Link to="/" className="Menu-logo-container" style={{ backgroundImage: "url(" + logoBG + ")"}}>
                <img src={logoFG} className="Menu-logo Menu-item" alt="homepage link" />
            </Link>
        );

        // Either login/signup buttons, or a logout links
        const accountLinksWhenLoggedIn = [
            (<Link className={ menuItemsClass } to="#" key="LoggedoutMenuItem-1" onClick={() => { this.onNewAuthToken(false); }}>Sign out</Link>),
            (
                <SentRequestsContext.Consumer key="SentRequestsContext.Consumer">
                    { sentRequests =>
                        <PendingRequestsContext.Consumer>
                            { pendingRequests => {
                                const unreadRequest = pendingRequests.find(req => !req.readByOwner);
                                const unreadApprovment = sentRequests.find(req => req.approved && !req.seenByRequester);
                                const haveNotification = (unreadRequest || unreadApprovment) !== undefined;
                                return (
                                    <Link to={"/profile/" + userId + "/" + username} key="LoggedoutMenuItem-2">
                                        <Avatar variant="menu" username={ username } showNotification={haveNotification} />
                                    </Link>
                                );
                            }}
                        </PendingRequestsContext.Consumer>
                    }
                </SentRequestsContext.Consumer>
                                
            )
        ];
        const accountLinksWhenLoggedOut = [
            (<Link className={ menuItemsClass } to="#" key="LoggedInMenuItem-1" onClick={_ => this.setState({loginModalOpen: true})}> Login </Link>),
            (<Link className={ menuItemsClass } to="#" key="LoggedInMenuItem-2" onClick={_ => this.setState({signupModalOpen: true})}> Signup </Link>)
        ]
        const accountLinks = this.context ? accountLinksWhenLoggedIn : accountLinksWhenLoggedOut;

        // other login-dependent links
        const loginDependentLinks = [
            (<Link to="/new-project" className={ menuItemsClass } key="NewProjectMenuItem"> New Project </Link>)
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
                                {/* Logo if in homepage */}
                                { homeLogoLink }

                                {/* For each login-dependent link, render place holder if shouldn't appear */}
                                { loginDependentLinks.map((link, i) => this.context ? link : <div key={"LoginDependantItemPH-" + i}></div> ) }

                                {/* Search bar */}
                                <SearchBar currentPath={this.props.location.pathname} />

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