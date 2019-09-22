import React from 'react';
import { Link, withRouter } from "react-router-dom";
import PropTypes from "prop-types";
import { Typography } from '@material-ui/core';

import Avatar from "./Avatar";


function UsersList(props) {
    if(props.users.length == 0)
        return <Typography variant="subtitle1">No Users</Typography>

    return (
        <div className="ListContainer">
            {props.users.map(user => (
                <Link to={"/profile/" + user.id + "/" + user.username} className="ListBlock" key={user.id}>
                    {/* Just leave this div here, it works. */}
                    <div></div>

                    <div className="ListBlockContent">
                        <Avatar username={user.username} variant={"listItem"} />
                        {/* Title */}
                        <Typography variant="h5">{user.username}</Typography>
                    </div>
                </Link>
            ))}
        </div>
    );
}


UsersList.propTypes = {
    users: PropTypes.arrayOf(PropTypes.shape({
        username: PropTypes.string.isRequired,
        id: PropTypes.string,
    })).isRequired
}


export default UsersList;