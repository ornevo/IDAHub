import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { Redirect } from 'react-router-dom';
import SearchIcon from '../res/searchIcon.png';


const SearchBar = ({ currentPath }) => {
    // Since on submit we need to return Redirect until the redirect has finished,
    //  we need an indication to when the redirect has finished, and we check it by
    //  saving the path to which we redirected and comparing with the current path
    // If it is undefined, it means the user hasn't submitted yet
    const [pathWhenSubmitted, setPathWhenSubmitted] = useState(undefined);
    const [inputValue, setInputValue] = useState('');

    function onChange(e) {
        setInputValue(e.target.value);
    }

    // On enter
    function onKeyDown(e) {
        if(e.key === 'Enter')
            setPathWhenSubmitted(currentPath);
    }

    // On submit, redirect to search page    
    if(pathWhenSubmitted) {
        if(pathWhenSubmitted === currentPath)
            return <Redirect to={"/search/" + inputValue} />;
        else // If finished redirecting
            setPathWhenSubmitted(undefined);
    }

    return (
        <input
            value={inputValue}
            className="SearchBar"
            onChange={onChange}
            onKeyDown={onKeyDown}
            style={{ backgroundImage: "url(" + SearchIcon + ")" }}
            placeholder="Search for users and projects"
        />
    )
}


SearchBar.propTypes = {
    currentPath: PropTypes.string.isRequired
}


export default SearchBar;