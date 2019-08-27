import React, { Component } from 'react';
import { Link } from "react-router-dom";
import ResponsiveMenu from 'react-responsive-navbar';


class Menu extends Component {
  render() {
    return (
      <ResponsiveMenu
        menuOpenButton={<div >O</div>}
        menuCloseButton={<div >X</div>}
        changeMenuOn="500px"
        largeMenuClassName="large-menu-classname"
        smallMenuClassName="small-menu-classname"
        menu={
          <div className="Menu-container">
            <Link className="Menu-item">Login / Signup</Link>
            <Link className="Menu-item">Some</Link>
            <Link className="Menu-item">more</Link>
            <Link className="Menu-item">links</Link>
          </div>
        }
      />
    );
  }
}

export default Menu;