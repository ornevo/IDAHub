/* This contains the overall, cross-page website look and router configuration */

/* React imports */
import React from 'react';
import { BrowserRouter as Router, Route } from "react-router-dom";

/* Custom components */
import Menu from "./components/Menu";
import HomepageLayout from "./layouts/homepage";

/* Styles importing */
import './stylesheets/App.css';
import './stylesheets/Homepage.css';


function App() {
  return (
    <div className="App">
      <Router>
        <Menu />
        <Route exact path="/" component={HomepageLayout} />
      </Router>
    </div>
  );
}

export default App;
