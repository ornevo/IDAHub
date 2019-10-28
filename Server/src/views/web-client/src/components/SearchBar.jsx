import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { Redirect } from 'react-router-dom';
import SearchIcon from '../res/searchIcon.png';
import SearchIconHomepage from "../res/searchIconWhite.png";


const SearchBar = ({ currentPath }) => {
    // Since on submit we need to return Redirect until the redirect has finished,
    //  we need an indication to when the redirect has finished, and we check it by
    //  saving the path to which we redirected and comparing with the current path
    // If it is undefined, it means the user hasn't submitted yet
    const [pathWhenSubmitted, setPathWhenSubmitted] = useState(undefined);
    const [isFocused, setIsFocused] = useState(false);
    const [inputValue, setInputValue] = useState('');

    function onChange(e) {
        const value = e.target.value;
        // Filter out illegal characters
        let filteredValue = '';
        for (let i = 0; i < value.length; i++)
            if(value[i].match(/^[a-z 0-9]+$/i))
                filteredValue += value[i];

        setInputValue(filteredValue);
    }

    // On enter
    function onKeyDown(e) {
        // Only re-submit if changed input
        if(e.key === 'Enter' && currentPath !== "/search/" + inputValue)
            setPathWhenSubmitted(currentPath);
    }

    // On submit, redirect to search page    
    let redirectRender = "";
    if(pathWhenSubmitted) {
        if(pathWhenSubmitted === currentPath) {
            // Redirect to main page if nothing to search
            if(!inputValue)
                redirectRender = <Redirect to="/" />;
            else
                redirectRender = <Redirect to={"/search/" + encodeURIComponent(inputValue)} />;
        } else // If finished redirecting
            setPathWhenSubmitted(undefined);
    }

    return (
        <span>
            { redirectRender }
            <input
                value={inputValue}
                className="SearchBar"
                onChange={onChange}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                onKeyDown={onKeyDown}
                style={{ backgroundImage: "url(" + (currentPath === "/" && !isFocused ? SearchIconHomepage : SearchIcon) + ")" }}
                placeholder="Search for users and projects"
            />
        </span>
    )
}


SearchBar.propTypes = {
    currentPath: PropTypes.string.isRequired
}


export default SearchBar;