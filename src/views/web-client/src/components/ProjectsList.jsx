import React from 'react';
import { Link, withRouter } from "react-router-dom";
import PropTypes from "prop-types";
import { Typography } from '@material-ui/core';
import { FaBriefcase } from 'react-icons/fa';


const DESCRIPTION_MAX_LENGTH = 200;


const boolToIsPublicString = b => b ? "Public" : "Private";


function ProjectsList(props) {
    return (
        <div className="ProjectsListContainer">
            {props.projects.map(project => (
                <Link to={"/project/" + project.id} className="ProjectBlock" key={project.id}>
                    {/* Public / Private */}
                    <Typography variant="caption" className={"ProjectModeLabel-" + boolToIsPublicString(project.public)}>
                        {boolToIsPublicString(project.public)}
                    </Typography>

                    <div className="ProjectBlock-content">
                        <div className="ProjectBlock-top-icon">
                            <FaBriefcase />
                        </div>

                        {/* Title */}
                        <Typography variant="h5">{project.name}</Typography>

                        {/* Description */}
                        <Typography variant="body1">
                            { (project.description || "").length > DESCRIPTION_MAX_LENGTH ?
                                project.description.substring(0, DESCRIPTION_MAX_LENGTH) + "..." : 
                                project.description
                            }
                        </Typography>
                    </div>
                </Link>
            ))}
        </div>
    );
}


ProjectsList.propTypes = {
    projects: PropTypes.arrayOf(PropTypes.shape({
        name: PropTypes.string.isRequired,
        description: PropTypes.string,
        public: PropTypes.bool.isRequired,
        contibutors: PropTypes.arrayOf(PropTypes.shape({
            username: PropTypes.string.isRequired,
            id: PropTypes.string.isRequired
        })),
        owner: PropTypes.string.isRequired
    })).isRequired
}


export default ProjectsList;