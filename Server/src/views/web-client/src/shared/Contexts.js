/* Contexes */
import React from 'react';

// This context will contain the authentication token if logged in
export const CredContext = React.createContext(undefined);

// This context will contain the requests sent by the logged in user
export const SentRequestsContext = React.createContext([]);

// This context will contain the requests sent to join projects we own, and we haven't approved / dismissed yet
export const PendingRequestsContext = React.createContext([]);