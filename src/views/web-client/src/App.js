/* This contains the overall, cross-page website look and router configuration */

/* React imports */
import React from 'react';
import { BrowserRouter as Router, Route } from "react-router-dom";
import { MuiThemeProvider } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';

import { CredContext } from "./shared/Contexts";
import { CustomMuiTheme } from "./shared/Constants";
import { NotificationContainer } from "react-notifications";


/* Custom components */
import Menu from "./components/Menu";
import HomepageLayout from "./layouts/homepage";
import NewProjectLayout from "./layouts/NewProject";

/* Styles importing */
import './stylesheets/App.css';
import './stylesheets/Homepage.css';


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
                <Route exact path="/new-project" component={NewProjectLayout} />

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
