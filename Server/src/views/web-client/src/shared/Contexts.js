/* Contexes */
import React from 'react';

// This context will contain the authentication token if logged in
export const CredContext = React.createContext(undefined);

// This context will contain the requests snet by the logged in user
export const SentRequestsContext = React.createContext([]);