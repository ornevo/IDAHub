/* This contains the overall, cross-page website look and router configuration */

/* React imports */
import React, { useState } from 'react';
import { BrowserRouter as Router, Route, Redirect, Switch } from "react-router-dom";
import { MuiThemeProvider } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';

import { CredContext, SentRequestsContext, PendingRequestsContext } from "./shared/Contexts";
import { CustomMuiTheme } from "./shared/Constants";
import { NotificationContainer } from "react-notifications";
import { useCookies } from 'react-cookie';

/* Custom components */
import Menu from "./components/Menu";

import Puller from "./components/Puller";

import HomepageLayout from "./layouts/homepage";
import NewProjectLayout from "./layouts/NewProject";
import ProfileLayout from "./layouts/Profile";
import ProjectLayout from "./layouts/Project";
import SearchLayout from "./layouts/Search";
import DownloadLayout from "./layouts/Download";

/* Styles importing */
import './stylesheets/App.css';
import './stylesheets/Menu.css';
import './stylesheets/Project.css';
import './stylesheets/Homepage.css';
import './stylesheets/Notifications.css';
import './stylesheets/NewProject.css';
import BackgroundCyberVideo from './components/BackgroundCyberVideo';


const App = (props) => {
  const [{ authToken }, setCookie] = useCookies(['authToken']);
  const [sentRequests, setSentRequests] = useState([]);
  const [pendingRequests, setPendingRequests] = useState([]);

  // This returns a component that redirects to '/' if not authenticated, but returns component otherwise
  function __authReqWrapper(component) {
    return (
      authToken ?
        component :
        () => <Redirect to="/" />
    );
  }

  function deleteAllCookies() {
    var cookies = document.cookie.split(";");

    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i];
        var eqPos = cookie.indexOf("=");
        var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
    }
  }

  function setAuthToken(newToken) {
    deleteAllCookies();

    if(newToken)
      setCookie('authToken', newToken);
    else
      setCookie('authToken', '');
  }

  return (
    <div className="App">
      <MuiThemeProvider theme={CustomMuiTheme}>
        {/* CssBaseline unifies the style to be consistent */}
        <CssBaseline />
        <Puller 
          authToken={authToken}
          currentSentRequestsList={sentRequests}
          updateSentRequestsList={setSentRequests}
          updatePendingRequestsList={setPendingRequests}
          currentPendingRequestsList={pendingRequests}
        />
        
        {/* A context to hold authentication token if logged in */}
        <CredContext.Provider value={authToken}>
          <SentRequestsContext.Provider value={sentRequests}>
            <PendingRequestsContext.Provider value={pendingRequests}>
              <Router>

                <Menu setAuthToken={setAuthToken}/>
                <div className="Full-screen-container GradientBackground">
                  <BackgroundCyberVideo />

                  <Switch>
                    <Route exact path="/" component={HomepageLayout} />
                    <Route exact path="/download" component={DownloadLayout} />
                    {/* In order to re-render it on route change since key changes, using this hack: */}
                    {/* Check this out: https://stackoverflow.com/a/39150493/3477857 */}
                    <Route path="/profile/:userId/:username" component={
                      (props) => <ProfileLayout key={props.match.params.userId} {...props} />}
                    />

                    <Route exact path="/project/:projectId" component={
                      (props) => <ProjectLayout key={props.match.params.projectId} {...props} />}
                    />

                    <Route exact path="/new-project" component={__authReqWrapper(NewProjectLayout)} />
                    {/* See notes above the profile route */}
                    <Route path="/search/:query" component={
                      props => <SearchLayout key={props.match.params.query} {...props} />
                    } />

                    {/* 404 back to main */}
                    <Route component={() => <Redirect from='*' to='/' />} />
                  </Switch>
                </div>
              </Router>
            </PendingRequestsContext.Provider>
          </SentRequestsContext.Provider>
        </CredContext.Provider>

        {/* To display notifications */}
      </MuiThemeProvider>
      <NotificationContainer />
    </div>
  );
}

export default App;
