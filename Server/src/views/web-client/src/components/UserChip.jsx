import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { Redirect } from "react-router-dom";

import Chip from '@material-ui/core/Chip';
import Avatar from "./Avatar";


const UserChip = ({ username, id, onDelete, clickable, isPrimary }) => {
    // Support on click redirect to profile
    const [hasClickedUser, setHasClickedUser] = useState(false);

    if(hasClickedUser)
        return <Redirect to={"/profile/" + id + "/" + username} />;

    return (
        <Chip
            className="UserChip"
            tabIndex={-1}
            color={isPrimary ? "primary" : undefined}
            variant={isPrimary ? "outlined" : undefined}
            label={username}
            onDelete={onDelete}
            onClick={clickable ? (() => setHasClickedUser(true)) : null}
            avatar={<Avatar username={username} variant="chip" />}
        />
    )
}


UserChip.propTypes = {
    username: PropTypes.string.isRequired,
    id: PropTypes.string.isRequired,
    // If no function passed, no delete button will be rendered
    onDelete: PropTypes.func,
    // If true, onclick will redirect to the user's profile page.
    clickable: PropTypes.bool,
    isPrimary: PropTypes.bool
}

UserChip.defaultProps = {
    clickable: true,
    isPrimary: false
}


export default UserChip;