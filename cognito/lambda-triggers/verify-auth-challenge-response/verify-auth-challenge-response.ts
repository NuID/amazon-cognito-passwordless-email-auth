// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CognitoUserPoolTriggerHandler } from 'aws-lambda';
import Zk from '@nuid/zk';

export const handler: CognitoUserPoolTriggerHandler = async event => {
  const proof = JSON.parse(event.request.challengeAnswer);
  const challenge = JSON.parse(event.request.privateChallengeParameters.challenge);

  // Combine the client-generated, single-use zero knowledge proof with the
  // challenge generated in `create-auth-challenge` to produce data that can be
  // verified as with `Zk.isVerified`.
  const verifiable = Zk.verifiableFromProofAndChallenge(proof, challenge);

  // The success of the authentication attempt is simply the result of verifying
  // the combined proof and challenge
  event.response.answerCorrect = Zk.isVerified(verifiable);

  return event;
};
