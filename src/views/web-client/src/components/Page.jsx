import React from 'react';
import PropTypes from 'prop-types';
import Container from '@material-ui/core/Container';
import CssBaseline from '@material-ui/core/CssBaseline';


const Page = (props) => (
    <Container className="Page-container">
        <div className="Page-sub-container Page-header-container">
            <h1 className="Main-header">
                { props.title }
            </h1>
        </div>
        <div className="Page-sub-container Page-content-container" >
            { props.children }
        </div>
    </Container>
    
)

Page.propTypes = {
    title: PropTypes.any.isRequired,
    children: PropTypes.element.isRequired
}


export default Page;