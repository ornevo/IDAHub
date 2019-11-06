import React from 'react';
import { Link } from "react-router-dom";
import { Helmet } from 'react-helmet';
import { FaCloudDownloadAlt } from 'react-icons/fa';
import Button from '@material-ui/core/Button';

import logo from '../res/logo.png';


export default () => {
    return (
        <div className="Homepage">
            <Helmet><title>IDAHub Homepage</title></Helmet>
            <img src={logo} className="Homepage-logo" alt="logo" />
            <h1 className="Homepage-main-header">IDA<strong>Hub</strong></h1>
            <h2 className="Homepage-secondary-header">Collebrative, cloud-based, real-time reverse engineering</h2>
            <Link to="/download">
                <Button className="DownloadButton-homepage" size="large">
                    <FaCloudDownloadAlt />
                    Download
                </Button>
            </Link>
        </div>
    );
}
