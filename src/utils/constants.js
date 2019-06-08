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
    }
}

export const Protocol = {
    Status: {
        Success: "OK",
        Failure: "Failed",
        FailureStatusCode: 500,
        UnauthorizedStatusCode: 401
    }
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

// For pagination
export const ResultsPageSize = 10; 