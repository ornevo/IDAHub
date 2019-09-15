/* A general popup for a consistent look */
import React from 'react';
import PropTypes from 'prop-types';
import Downshift from 'downshift';
import TextField from '@material-ui/core/TextField';
import Container from '@material-ui/core/Container';
import Paper from '@material-ui/core/Paper';
import MenuItem from '@material-ui/core/MenuItem';
import Chip from '@material-ui/core/Chip';

import { NotificationManager } from "react-notifications";

import { searchUsersByUsername } from "../shared/API";


// Time to wait after finishing to write in order to update users, in ms
const WAIT_BEFORE_FETCHING_USERS = 250;


function renderSuggestion(suggestionProps) {
    const { suggestion, index, itemProps, highlightedIndex, selectedItem } = suggestionProps;
    const isHighlighted = highlightedIndex === index;
    const isSelected = (selectedItem || '').indexOf(suggestion.label) > -1;

    return (
        <MenuItem
            {...itemProps}
            key={suggestion.id}
            selected={isHighlighted}
            component="div"
            style={{
                fontWeight: isSelected ? 500 : 400,
            }}
        >
            {suggestion.username}
        </MenuItem>
    );
}



class UserSelector extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            currInputValue: '',
            chosenUsers: [],
            fetchedUsers: []
        }
    }

    onInputChange(newInput) {
        newInput = newInput.trim();
        this.setState({ currInputValue: newInput });
        if(!newInput)
            return;

        // Only update users after some delay in typing
        setTimeout(() => {
            // Not relevant if text changed
            if(this.state.currInputValue !== newInput)
                return;

            searchUsersByUsername(newInput).then(foundUsers => {
                if(this.state.currInputValue !== newInput)
                    return;
                
                this.setState({fetchedUsers: (foundUsers || {}).data || []})                
            }).catch(error => {
                NotificationManager.error(error.body);
            })
        }, WAIT_BEFORE_FETCHING_USERS);
    }

    onUserChosen(chosenUserId) {
        const chosenUserObject = this.state.fetchedUsers.find(user => user.id === chosenUserId);

        let newChosenUsers = this.state.chosenUsers;

        if (newChosenUsers.find(user => user.id === chosenUserId) === undefined)
            newChosenUsers = [...newChosenUsers, chosenUserObject];

        this.setState({
            currInputValue: '',
            chosenUsers: newChosenUsers
        }, () => this.props.onChange(this.state.chosenUsers));
    }

    // To simulate delete of a already-selected user
    handleKeyDown(event) {
        // If no regular input, and there's a selected user, delete it
        let chosenUsers = this.state.chosenUsers;
        if (chosenUsers.length && !this.state.currInputValue.length && event.key === 'Backspace')
            this.onDelete(chosenUsers[chosenUsers.length - 1]);
    }

    onDelete(deletedUser) {
        let newChosenUsers = this.state.chosenUsers.filter(user => user.id !== deletedUser.id);
        this.setState({ chosenUsers: newChosenUsers }, () => this.props.onChange(this.state.chosenUsers));
    }

    render() {
        return (
            <Downshift
                inputValue={this.state.currInputValue}
                onChange={this.onUserChosen.bind(this)}
                selectedItem={this.state.chosenUsers.map(cUser => cUser.username)}
            >
                {({
                    getInputProps,
                    getItemProps,
                    getLabelProps,
                    isOpen,
                    selectedItem: selectedItem2,
                    highlightedIndex,
                }) => {
                    const { onBlur, onChange, onFocus, ...inputProps } = getInputProps({
                        onKeyDown: this.handleKeyDown.bind(this),
                        placeholder: this.state.chosenUsers.length > 0 ? '' : 'Search username',
                    });

                    return (
                        <div>
                            <Container>
                                <TextField
                                    InputProps={{
                                        startAdornment: this.state.chosenUsers.map(user => (
                                            <Chip
                                                key={user.id}
                                                tabIndex={-1}
                                                label={user.username}
                                                onDelete={(() => this.onDelete(user))}
                                            />
                                        ))
                                    }}
                                    onBlur={onBlur}
                                    onChange={(event => {
                                        this.onInputChange(event.target.value)
                                        onChange(event);
                                    })}
                                    onFocus={onFocus}
                                    {...inputProps}
                                    fullWidth={true}
                                    label={'Users'}
                                    InputLabelProps={getLabelProps()}
                                />

                                {isOpen ? (
                                    <Paper square>
                                        {this.state.fetchedUsers.filter(u => u.username.startsWith(this.state.currInputValue)).map((suggestion, index) =>
                                            renderSuggestion({
                                                suggestion,
                                                index,
                                                itemProps:  getItemProps({item: suggestion.id}),
                                                highlightedIndex,
                                                selectedItem: selectedItem2,
                                            }),
                                        )}
                                    </Paper>
                                ) : null}
                            </Container>
                        </div>
                    );
                }}
            </Downshift>
        );
    }
}


UserSelector.propTypes = {
    onChange: PropTypes.func.isRequired
};


export default UserSelector;