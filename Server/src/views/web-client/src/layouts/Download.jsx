import React from 'react';
import Button from '@material-ui/core/Button';
import { FaCloudDownloadAlt } from 'react-icons/fa';
import { Typography } from '@material-ui/core';

import Page from '../components/Page';


const Snippet = ({ code }) => <span className="snippet">{ code }</span>;


const DownloadLayout = () => (
    <Page title="Download IDA Plugin">
        <form method="get" action="/static/client.tar.gz" className="DownloadButton-container">
            <Button className="DownloadButton-download-page GradientBackground" type="submit" size="large" >
                <FaCloudDownloadAlt />
                Download
            </Button>
        </form>

        <Typography variant="h4">Prerequisites</Typography>
        <Typography variant="body1">
            <ul>
                <li><Snippet code="python" /> installed and in the PATH.</li>
                <li><Snippet code="pip" /> installed and in the PATH.</li>
                <li>An <Snippet code="IDAHub" /> account.</li>
            </ul>
        </Typography>

        <Typography variant="h4">Installation</Typography>
        <Typography variant="body1">
            <ol>
                <li>Download the <Snippet code="client.tar.gz"/> archive and extract it somewhere temporary.</li>
                <li><Snippet code="cd" /> into the extracted folder, and run <Snippet code="python install_key.py" /></li>
                <li>Install the plugin's dependencies by running <Snippet code="pip install -r requirements.txt" /></li>
                <li>
                    Install the plugin in IDA by copying all of the downloaded files into <Snippet code="{IDA Installation Dir}/plugins" />.
                    IDA's installation folder can be found by right-clicking IDA and selecting <Snippet code="Open file location" />.
                </li>
                <li>Open IDA, and login with you IDAHub account credentials. If you have no account, sign up here first.</li>
            </ol>
        </Typography>
    </Page>
);


export default DownloadLayout;