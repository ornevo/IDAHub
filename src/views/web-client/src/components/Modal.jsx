/* A general popup for a consistent look */
import React from 'react';
import PropTypes from "prop-types";
import ReactModal from 'react-modal';
import { FaRegTimesCircle } from 'react-icons/fa';


const minModalWidth = 500;
const maxModalWidth = 810;
// Precentage of the screen in between the two values
const defaultModalFraction = 0.6; 


class Modal extends React.Component {
    constructor(props) {
        super(props);
        this.state = this.getUpToDateState();
    }

    // up to date considering current windowsize
    getUpToDateState() {
        const screenWidth = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
        const standartModalWidth = Math.min(Math.max(minModalWidth, defaultModalFraction * screenWidth), maxModalWidth);
        const modalWidth = Math.min(screenWidth, standartModalWidth);
            
        return { screenWidth, modalWidth };
    }

    // To dynamically change modal size to screen size, we track resize events
    // We assume only one modal at a time "lives"
    componentDidMount() {
        window.addEventListener("resize", this.handleResize.bind(this));
    }
    componentWillUnmount() {
        window.addEventListener("resize", null);
    }
    handleResize(WindowSize, event) {
        this.setState(this.getUpToDateState());
    }

    render() {
        // The style applied to the modal is for the modal to always be at front
        // We user style and not proper css class because it overrides all of the
        //  component's own styles, and requires us to reimplement them.
        // We want to build it depending on screen width, so it needs to be calculated dynamically
        const modalStyle = {
            bottom: "0px",
            top: "40px",
            left: ((this.state.screenWidth - this.state.modalWidth) / 2) + "px",
            width: this.state.modalWidth,
            padding: 0,
            borderRadius: "40px 40px 0 0",
        };
        return (
            <ReactModal style={{overlay: { zIndex: 10000 }, content: modalStyle}} 
                isOpen={this.props.isOpen} onRequestClose={this.props.onClose}>

                {/* Exit button */}
                <FaRegTimesCircle size={32}
                    onClick={this.props.onClose} className="Modal-exit-button" />

                <div className="Modal-inner-container">
                    {this.props.children}
                </div>

            </ReactModal>
        );
    }
}


Modal.propTypes = {
    isOpen: PropTypes.bool,
    onClose: PropTypes.func.isRequired,
    chlidren: PropTypes.element.isRequired
};

Modal.defaultProps = {
    isOpen: false,
    children: ''
}


export default Modal;