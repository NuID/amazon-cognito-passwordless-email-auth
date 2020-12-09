// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CognitoUserPoolTriggerHandler } from 'aws-lambda';
import Zk from '@nuid/zk';

export const handler: CognitoUserPoolTriggerHandler = async event => {
    const credential = JSON.parse(event.request.userAttributes['custom:credential']);
    const challenge = Zk.defaultChallengeFromCredential(credential);
    const json = JSON.stringify(challenge);

    // The `challenge` parameter is non-sensitive and specific to a single
    // authentication attempt (i.e. single use). The same challenge is issued as
    // both as a public and private challenge parameter. The client will use it
    // to generate a similarly single-use zero knowledge proof that is specific
    // to the challenge generated here. It's also issued as a private challenge
    // parameter so that we can statelessly retrieve it in
    // `verify-auth-challenge-response` to verify that the proof was generated
    // for the challenge generated here, and therefore relevant to the ongoing
    // authentication attempt.
    //
    // NOTE: `privateChallengeParameters` and similar trusted session data may
    // also be used to further constrain the context of the authentication
    // attempt. E.g. the challenge could be bound to a given point in time by
    // adding a timestamp to `privateChallengeParameters`, which
    // `verify-auth-challenge-response` could use to additionally verify that a
    // proof is received within a specified period of challenge generation.
    //
    // NOTE: In the absence of trusted session data such as
    // `privateChallengeParameters`, signature-based integrity validation may
    // serve a similar purpose (e.g. JWT).

    // This is sent back to the client app
    event.response.publicChallengeParameters = {
      email: event.request.userAttributes.email,
      challenge: json
    };

    // This is trusted session data that can be retrieved in
    // `verify-auth-challenge-response`
    event.response.privateChallengeParameters = {
      challenge: json
    };

    return event;
};
