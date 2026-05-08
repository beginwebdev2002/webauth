"use strict";
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.expectedOrigin = exports.rpID = void 0;
const https_1 = __importDefault(require("https"));
const http_1 = __importDefault(require("http"));
const fs_1 = __importDefault(require("fs"));
const express_1 = __importDefault(require("express"));
const express_session_1 = __importDefault(require("express-session"));
const memorystore_1 = __importDefault(require("memorystore"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const server_1 = require("@simplewebauthn/server");
const app = (0, express_1.default)();
const MemoryStore = (0, memorystore_1.default)(express_session_1.default);
const { ENABLE_CONFORMANCE, ENABLE_HTTPS, RP_ID, } = process.env;
app.use(express_1.default.static('./public/'));
app.use(express_1.default.json());
app.use((0, express_session_1.default)({
    secret: 'secret123',
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: 86400000,
        httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
        checkPeriod: 86400000, // prune expired entries every 24h
    }),
}));
/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
    Promise.resolve().then(() => __importStar(require('./fido-conformance'))).then(({ fidoRouteSuffix, fidoConformanceRouter }) => {
        app.use(fidoRouteSuffix, fidoConformanceRouter);
    });
}
/**
 * RP ID represents the "scope" of websites on which a credential should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
exports.rpID = RP_ID || 'localhost';
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
exports.expectedOrigin = 'https://webauth-l4xa.onrender.com';
/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the credential.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';
const inMemoryUserDB = {
    [loggedInUserId]: {
        id: loggedInUserId,
        username: `user@${exports.rpID}`,
        credentials: [],
    },
};
/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
    const user = inMemoryUserDB[loggedInUserId];
    const { 
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    username, credentials, } = user;
    const opts = {
        rpName: 'SimpleWebAuthn Example',
        rpID: exports.rpID,
        userName: username,
        timeout: 60000,
        attestationType: 'none',
        /**
         * Passing in a user's list of already-registered credential IDs here prevents users from
         * registering the same authenticator multiple times. The authenticator will simply throw an
         * error in the browser if it's asked to perform registration when it recognizes one of the
         * credential ID's.
         */
        excludeCredentials: credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
        authenticatorSelection: {
            residentKey: 'discouraged',
            /**
             * Wondering why user verification isn't required? See here:
             *
             * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
             */
            userVerification: 'preferred',
        },
        /**
         * Support the two most common algorithms: ES256, and RS256
         */
        supportedAlgorithmIDs: [-7, -257],
    };
    const options = await (0, server_1.generateRegistrationOptions)(opts);
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify the registration response.
     */
    req.session.currentChallenge = options.challenge;
    res.send(options);
});
app.post('/verify-registration', async (req, res) => {
    const body = req.body;
    const user = inMemoryUserDB[loggedInUserId];
    const expectedChallenge = req.session.currentChallenge;
    let verification;
    try {
        const opts = {
            response: body,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: exports.expectedOrigin,
            expectedRPID: exports.rpID,
            requireUserVerification: false,
        };
        verification = await (0, server_1.verifyRegistrationResponse)(opts);
    }
    catch (error) {
        const _error = error;
        console.error(_error);
        return res.status(400).send({ error: _error.message });
    }
    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
        const { credential } = registrationInfo;
        const existingCredential = user.credentials.find((cred) => cred.id === credential.id);
        if (!existingCredential) {
            /**
             * Add the returned credential to the user's list of credentials
             */
            const newCredential = {
                id: credential.id,
                publicKey: credential.publicKey,
                counter: credential.counter,
                transports: body.response.transports,
            };
            user.credentials.push(newCredential);
        }
    }
    req.session.currentChallenge = undefined;
    res.send({ verified });
});
/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {
    // You need to know the user by this point
    const user = inMemoryUserDB[loggedInUserId];
    const opts = {
        timeout: 60000,
        allowCredentials: user.credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
        /**
         * Wondering why user verification isn't required? See here:
         *
         * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
         */
        userVerification: 'preferred',
        rpID: exports.rpID,
    };
    const options = await (0, server_1.generateAuthenticationOptions)(opts);
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify the authentication response.
     */
    req.session.currentChallenge = options.challenge;
    res.send(options);
});
app.post('/verify-authentication', async (req, res) => {
    const body = req.body;
    const user = inMemoryUserDB[loggedInUserId];
    const expectedChallenge = req.session.currentChallenge;
    let dbCredential;
    // "Query the DB" here for a credential matching `cred.id`
    for (const cred of user.credentials) {
        if (cred.id === body.id) {
            dbCredential = cred;
            break;
        }
    }
    if (!dbCredential) {
        return res.status(400).send({
            error: 'Authenticator is not registered with this site',
        });
    }
    let verification;
    try {
        const opts = {
            response: body,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: exports.expectedOrigin,
            expectedRPID: exports.rpID,
            credential: dbCredential,
            requireUserVerification: false,
        };
        verification = await (0, server_1.verifyAuthenticationResponse)(opts);
    }
    catch (error) {
        const _error = error;
        console.error(_error);
        return res.status(400).send({ error: _error.message });
    }
    const { verified, authenticationInfo } = verification;
    if (verified) {
        // Update the credential's counter in the DB to the newest count in the authentication
        dbCredential.counter = authenticationInfo.newCounter;
    }
    req.session.currentChallenge = undefined;
    res.send({ verified });
});
if (ENABLE_HTTPS) {
    const host = '0.0.0.0';
    const port = 443;
    exports.expectedOrigin = `https://${exports.rpID}`;
    https_1.default
        .createServer({
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs_1.default.readFileSync(`./${exports.rpID}.key`),
        cert: fs_1.default.readFileSync(`./${exports.rpID}.crt`),
    }, app)
        .listen(port, host, () => {
        console.log(`🚀 Server ready at ${exports.expectedOrigin} (${host}:${port})`);
    });
}
else {
    const host = '0.0.0.0';
    const port = 8000;
    exports.expectedOrigin = `http://localhost:${port}`;
    http_1.default.createServer(app).listen(port, host, () => {
        console.log(`🚀 Server ready at ${exports.expectedOrigin} (${host}:${port})`);
    });
}
//# sourceMappingURL=index.js.map