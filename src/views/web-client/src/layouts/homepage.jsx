import React from 'react';
import logo from '../res/logo.png';

export default () => (
    <div className="Full-screen-container Homepage">

        <link href="https://fonts.googleapis.com/css?family=Dosis|Imprima|Nanum+Gothic|Pontano+Sans|Quicksand|Raleway&display=swap" rel="stylesheet" />

        <img src={logo} className="Homepage-logo" alt="logo" />
        <h1 className="Homepage-main-header">IDA<strong>Hub</strong></h1>
        <h2 className="Homepage-secondary-header">Collebrative, cloud-based, real-time reverse engineering</h2>
    </div>
);
