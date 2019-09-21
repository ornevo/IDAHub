/* This contains the overall, cross-page website look and router configuration */

/* React imports */
import React from 'react';
import { BrowserRouter as Router, Route, Redirect } from "react-router-dom";
import { MuiThemeProvider } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';

import { CredContext } from "./shared/Contexts";
import { CustomMuiTheme } from "./shared/Constants";
import { NotificationContainer } from "react-notifications";


/* Custom components */
import Menu from "./components/Menu";

import HomepageLayout from "./layouts/homepage";
import NewProjectLayout from "./layouts/NewProject";
import ProfileLayout from "./layouts/Profile";

/* Styles importing */
import './stylesheets/App.css';
import './stylesheets/Menu.css';
import './stylesheets/Homepage.css';
import './stylesheets/NewProject.css';


class App extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      authToken: false
    }
  }
  
  setAuthToken(newToken) {
    this.setState({authToken: newToken});
  }

  // This returns a component that redirects to '/' if not authenticated, but returns component otherwise
  __authReqWrapper(component) {
    return (
      this.state.authToken !== false ?
        component :
        () => <Redirect to="/" />
    );
  }

  render() {
    return (
      <div className="App">
        <MuiThemeProvider theme={CustomMuiTheme}>
          {/* CssBaseline unifies the style to be consistent */}
          <CssBaseline />
          
          {/* A context to hold authentication token if logged in */}
          <CredContext.Provider value={this.state.authToken}>
            <Router>

              <Menu setAuthToken={this.setAuthToken.bind(this)}/>              
              <div className="Full-screen-container">

                <Route exact path="/" component={HomepageLayout} />
                {/* In order to re-render it on route change since key changes, using this hack: */}
                {/* Check this out: https://stackoverflow.com/a/39150493/3477857 */}
                <Route exact path="/profile/:userId/:username" component={
                  (props) => <ProfileLayout key={props.match.params.userId} {...props} />}
                />
                <Route exact path="/new-project" component={this.__authReqWrapper(NewProjectLayout)} />
                {/* A not found route back to main */}
                {/* <Route path="*" component={() => <Redirect to="/" />} />  */}

              </div>
            </Router>
          </CredContext.Provider>

          {/* To display notifications */}
        </MuiThemeProvider>
        <NotificationContainer />
      </div>
    );
  }
}

export default App;
