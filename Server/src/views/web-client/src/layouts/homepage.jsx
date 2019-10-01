import React from 'react';
import logo from '../res/logo.png';
import { Helmet } from 'react-helmet';


export default () => {
    return (
        <div className="Homepage">
            <Helmet><title>IDAHub Homepage</title></Helmet>
            <img src={logo} className="Homepage-logo" alt="logo" />
            <h1 className="Homepage-main-header">IDA<strong>Hub</strong></h1>
            <h2 className="Homepage-secondary-header">Collebrative, cloud-based, real-time reverse engineering</h2>
        </div>
    );
}
