import React from 'react';
import PropTypes from 'prop-types';
import Container from '@material-ui/core/Container';
import { Helmet } from 'react-helmet';


const Page = (props) => (
    <Container className="Page-container">
        {/* Browser tab title */}
        <Helmet><title>{ props.title || "IDAHub" }</title></Helmet>

        {/* Page title */}
        <div className="Page-sub-container Page-header-container">
            <h1 className="Main-header">
                { props.title }
            </h1>
        </div>

        {/* Content */}
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