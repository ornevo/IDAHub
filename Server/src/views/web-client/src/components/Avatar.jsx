import React from 'react';

import { GoPerson } from "react-icons/go";

import PropTypes from "prop-types";


const BG_COLORS = [
    // [background color, icon color]
    ["#274c77", "white"],
    ["#6096ba", "white"],
    ["#d4cdc3", "black"],
    ["#a2a392", "black"],
    ["#083d77", "white"],
    ["#f4d35e", "black"],
    ["#eb5e55", "black"],
    ["#3a3335", "white"]
]


function hashStr(str) {
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
        var charCode = str.charCodeAt(i);
        hash += charCode;
    }
    return hash;
}

function stringToColor(string) {
    return BG_COLORS[hashStr(string) % BG_COLORS.length];
}

const Avatar = ({ username, variant }) => {
    // decide the color consistently according to the username
    const [background, fontColor] = stringToColor(username);
    
    let containerStyle = {
        background:     background,
        color:          fontColor,
        borderRadius:   "50%",
        textAlign:      "center",
        verticalAlign:  "middle",
        display: "inline-block"
    }

    // For now same style for menu and chip
    if(variant === "menu" || variant === "chip") {
        containerStyle.width = "30px";
        containerStyle.height = "30px";
        containerStyle.fontSize = "12px";
        containerStyle.padding = "8px 9px";
    } else if(variant === "listItem") {
        containerStyle.width = "70px";
        containerStyle.height = "70px";
        containerStyle.fontSize = "20px";
        containerStyle.padding = "22px";
        containerStyle.marginBottom = "7px";
    } else {
        throw new Error("Bad Avatar variant.");
    }

    return (
        <div style={containerStyle} >
            <GoPerson />
        </div>
    );
}


Avatar.propTypes = {
    username: PropTypes.string.isRequired,
    variant: PropTypes.oneOf(["menu", "chip", "listItem"])
}

Avatar.defaultProps = {
    username: 'default',
    variant: "menu"
}


export default Avatar;