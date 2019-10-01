/**
 * Definition of global constants for the project
 */
export const Models = {
    Project: {
        name: "Project"
    },
    User: {
        name: "User"
    },
    UserInProject: {
        name: "UserInProject"
    },
    Modification: {
        name: "Modification"
    },
    Session: {
        name: "Session"
    }
}

export const Protocol = {
    Status: {
        Success: "OK",
        Failure: "Failed",
        FailureStatusCode: 500,
        UnauthorizedStatusCode: 401,
        NotFoundStatusCode: 404
    },
    httpAuthorizationScheme: "Bearer",
}

// Some JWT settings
const SigningSettings = {
    issuer:  "IDAHub",
    subject:  "IDAHub",
    audience:  "", // Should be field to the user's username
    expiresIn:  "10d", // Expires in 10 days
    algorithm:  "RS256"
}
// Only difference is that algorithm is in an array
const VerifyingSettings = {
    issuer: SigningSettings.issuer,
    subject: SigningSettings.subject,
    audience: SigningSettings.audience, //Should be field to the user's username
    expiresIn: SigningSettings.expiresIn, // Expires in 10 days
    algorithm: [SigningSettings.algorithm],
}
export const JWTSettings = {
    SigningSettings,
    VerifyingSettings,
    // Relative to the project root
    publicKeyPath: "./cryptoKeys/key.pub",
    privateKeyPath: "./cryptoKeys/key.prv"
};

// Modifications event types
export const EventTypes = {
    CHANGE_FUNCTION_NAME_ID: 1,
    CHANGE_GLOBAL_VARIABLE_NAME_ID: 2,
    CHANGE_LABEL_NAME_ID: 3,
    SET_COMMENT_ID: 4,
    CHANGE_TYPE_ID: 5,
    NEW_FUNCTION_ID: 6,
    UNDEFINE_DATA_ID: 7,
    CHANGE_FUNCTION_START_ID: 8,
    CHANGE_FUNCTION_END_ID: 9,
    CREATE_STRUCT_ID: 10,
    CREATE_STRUCT_VARIABLE_ID: 11,
    DELETE_STRUCT_VARIABLE_ID: 12,
    CHANGE_STRUCT_ITEM_TYPE_ID: 13,
    DELETE_STRUCT_ID: 14,
    CHANGE_STRUCT_NAME_ID: 15,
    CREATE_ENUM_ID: 16,
    CREATE_ENUM_ITEM_ID: 17,
    CHANGE_ENUM_ITED_ID: 18,
    DELETE_ENUM_ID: 19,
    CHANGE_ENUM_NAME_ID: 20,
    CHANGE_FUNCTION_HEADER_ID: 21,
    IDA_CURSOR_CHANGE_ID: 22,
    EXIT_FROM_IDA_ID: 23,
    START_IDA_ID: 24,
    CHANGE_STRUCT_MEMBER_NAME_ID: 25,
    DELETE_ENUM_MEMBER_ID: 26
}

// For pagination
export const ResultsPageSize = 10; 