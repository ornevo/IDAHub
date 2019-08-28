/* This component supplies a general container for a stateless form,
        handling the sending of the form and the handling of the resonse.
    It receives the stateless form. It assumes that the form has a `onSubmit`
        prop to pass a function, and this function expects as a parameter the 
        submitted values. Optionally, These will be passed for processing to the StatelessFormAPIHandler's
        formDataToApiParams, and will the be passed to the api params.
    See the props at the end.
    This component will not send any notifications.
*/
import React from 'react';
import PropTypes from 'prop-types';


class StatelessFormAPIHandler extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            isLoading: false
        }
    }

    onSubmit(data) {
        // First let parent validate
        if (!this.props.validator(data)) {
            return;
        }

        this.setState({ isLoading: true });

        // Let user process 
        const parametersPassedToApiFunction = this.props.formDataToAPIParams(data);
        
        // Call api function, expect it to return promise
        this.props.apiFunc(parametersPassedToApiFunction)
            .then(this.props.onSuccess)
            .catch(errorObj => {
                const errorCode = errorObj.statusCode;
                const errorDesc = errorObj.body;

                this.props.onError(errorCode, errorDesc);
            })
            .finally((() => this.setState({ isLoading: false })).bind(this));
    }

    render() {
        const formType = this.props.formToRender;
        const formProps = {
            isLoading: this.state.isLoading,
            onSubmit: this.onSubmit.bind(this)
        };
        return React.createElement(formType, formProps);
    }
}


StatelessFormAPIHandler.propTypes = {
    // The form to render. Should have an onSubmit and isLoading prop.
    formToRender: PropTypes.elementType.isRequired,
    // The api function to call upon submittion
    apiFunc: PropTypes.func.isRequired,
    // To be called when received error from the api call. Called as: onError(statusCode, body)
    onError: PropTypes.func.isRequired,
    // Called upon successful api call, called as: onSuccess(responseBody)
    onSuccess: PropTypes.func.isRequired,
    // A function receiving the form data passed to onSubmit, returns true/false indicating
    //  if the submitted data is valid for sending.
    validator: PropTypes.func,
    // This function will receive the parameters the form passes to the onSubmit
    //  function, and its return value will be passed to the api function as extra data.
    formDataToAPIParams: PropTypes.func,
}

StatelessFormAPIHandler.defaultProps = {
    validator: () => true,
    formDataToAPIParams: (v) => v
}

export default StatelessFormAPIHandler;