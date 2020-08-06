const express   = require('express');
const { Fido2Lib } = require('fido2-lib');
const utils     = require('../utils');
const config    = require('../config.json');
const base64url = require('base64url');
const router    = express.Router();
const database  = require('./db');
const base64ToArrayBuffer = input => new Uint8Array(base64url.toBuffer(input)).buffer;

const {
    CredentialAttestation,
    CredentialAssertion,
} = require("webauthn-simple-app");

var f2l = new Fido2Lib({
    // timeout: 42,
    // rpId: "http://localhost:3000/",
    rpName: "Contoso",
    rpIcon: "https://cdn.auth0.com/website/assets/pages/press/img/resources/auth0-logo-main-6001cece68.svg",
    challengeSize: 128,
    attestation: "none",
    // cryptoParams: [-7, -257],
    // authenticatorAttachment: "platform",
    // authenticatorRequireResidentKey: false,
    // authenticatorUserVerification: "required"
});

router.post('/register/start', async (req, res) => {
    if(!req.body || !req.body.username || !req.body.name) {
        res.json({
            'status': 'failed',
            'message': 'Request missing name or username field!'
        })

        return
    }

    const name = req.body.name;
    const username = req.body.username;
    const exists = Object.values(database).find(u => u.name == username && u.registered);

    if(exists) {
        return res.json({
            'status': 'failed',
            'message': `User ${username} already exist!`
        });
    }

    const uid = utils.randomBase64URLBuffer();
    const user = database[uid] = {
        'name': name,
        'registered': false,
        'id': uid,
        'authenticators': []
    }

    const registrationOptions = await f2l.attestationOptions();
    registrationOptions.challenge = base64url(registrationOptions.challenge);
    registrationOptions.user.id = user.id;
    registrationOptions.user.displayName = user.name;
    registrationOptions.user.name = user.name;

    req.session.challenge = registrationOptions.challenge;
    req.session.user = uid;

    res.json(registrationOptions);
});


router.post('/register/finish', async (req, res) => {
    if(!req.body       || !req.body.id
    || !req.body.rawId || !req.body.response
    || !req.body.type  || req.body.type !== 'public-key' ) {
        return res.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        });
    }

    const attestationExpectations = {
        challenge: base64url.toBuffer(req.session.challenge),
        origin: config.origin,
        factor: "either"
    };

    const attResult = CredentialAttestation.from(req.body);
    attResult.decodeBinaryProperties();

    try {
        const regResult = await f2l.attestationResult(attResult, attestationExpectations); // will throw on error
        const publicKey = regResult.authnrData.get('credentialPublicKeyPem')
        const counter = regResult.authnrData.get('counter');
        const id =  req.body.id; //base64url(regResult.authnrData.get('credId'));
        const uid = req.session.user;
        const user = database[uid];
        user.registered = true;
        user.authenticators.push({ publicKey, counter, id });
        req.session.loggedIn = true;
        res.json({ 'status': 'ok' })
    } catch (err) {
        console.log(err);
        res.status(500);
    }
})

router.post('/login/start', async (req, res) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        })

        return
    }

    const username = req.body.username;
    const user = Object.values(database).find(u => u.name == username && u.registered);

    if(!user) {
        return res.json({
            'status': 'failed',
            'message': `User ${username} does not exist!`
        });
    }

    const authnOptions = await f2l.assertionOptions();
    const challenge = base64url(authnOptions.challenge);

    req.session.challenge = challenge;
    req.session.user = user.id;
    const response = {
        challenge,
        timeout: authnOptions.timeout,
        allowCredentials: user.authenticators.map(a => {
            return {
                id: a.id,
                type: "public-key",
            };
        })
    }
    res.json(response);
});



router.post('/login/finish', async (req, res) => {
    if(!req.body       || !req.body.id
    || !req.body.rawId || !req.body.response
    || !req.body.type  || req.body.type !== 'public-key' ) {
        return res.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })
    }

    var assn = CredentialAssertion.from(req.body);
    assn.validate();
    assn.decodeBinaryProperties();

    try {
        const uid = req.session.user;
        const user = database[uid];
        const authenticator = user.authenticators.find(a => a.id = req.body.id);

        if (!authenticator) {
            return res.sendStatus(401);
        }

        const attestationExpectations = {
            challenge: base64url.toBuffer(req.session.challenge),
            origin: config.origin,
            factor: "either",
            publicKey: authenticator.publicKey,
            prevCounter: authenticator.counter,
            userHandle: uid,
        };

        const result = await f2l.assertionResult(assn, attestationExpectations); // will throw on error
        authenticator.counter = result.authnrData.get("counter");

        req.session.loggedIn = true;
        res.json({ 'status': 'ok' })
    } catch (err) {
        console.log(err);
        return res.status(401);
    }
});

module.exports = router;
