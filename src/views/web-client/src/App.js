/* This contains the overall, cross-page website look and router configuration */

/* React imports */
import React from 'react';
import { BrowserRouter as Router, Route, Redirect } from "react-router-dom";
import { MuiThemeProvider } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';

import { CredContext } from "./shared/Contexts";
import { CustomMuiTheme } from "./shared/Constants";
import { NotificationContainer } from "react-notifications";
import { useCookies } from 'react-cookie';


/* Custom components */
import Menu from "./components/Menu";

import HomepageLayout from "./layouts/homepage";
import NewProjectLayout from "./layouts/NewProject";
import ProfileLayout from "./layouts/Profile";
import SearchLayout from "./layouts/Search";

/* Styles importing */
import './stylesheets/App.css';
import './stylesheets/Menu.css';
import './stylesheets/Homepage.css';
import './stylesheets/NewProject.css';


const App = (props) => {
  const [{ authToken }, setCookie] = useCookies(['authToken']);

  // This returns a component that redirects to '/' if not authenticated, but returns component otherwise
  function __authReqWrapper(component) {
    return (
      authToken ?
        component :
        () => <Redirect to="/" />
    );
  }

  function setAuthToken(newToken) {
    if(newToken)
      setCookie('authToken', newToken, { path: '/' });
    else
      setCookie('authToken', false);
  }

  return (
    <div className="App">
      <MuiThemeProvider theme={CustomMuiTheme}>
        {/* CssBaseline unifies the style to be consistent */}
        <CssBaseline />
        
        {/* A context to hold authentication token if logged in */}
        <CredContext.Provider value={authToken}>
          <Router>

            <Menu setAuthToken={setAuthToken}/>
            <div className="Full-screen-container">

              <Route exact path="/" component={HomepageLayout} />
              {/* In order to re-render it on route change since key changes, using this hack: */}
              {/* Check this out: https://stackoverflow.com/a/39150493/3477857 */}
              <Route exact path="/profile/:userId/:username" component={
                (props) => <ProfileLayout key={props.match.params.userId} {...props} />}
              />
              <Route exact path="/new-project" component={__authReqWrapper(NewProjectLayout)} />
              {/* See notes above the profile route */}
              <Route path="/search/:query" component={
                props => <SearchLayout key={props.match.params.query} {...props} />
              } />

              {/* 404 back to main */}
              <Redirect from='*' to='/' />
            </div>
          </Router>
        </CredContext.Provider>

        {/* To display notifications */}
      </MuiThemeProvider>
      <NotificationContainer />
    </div>
  );
}

export default App;
