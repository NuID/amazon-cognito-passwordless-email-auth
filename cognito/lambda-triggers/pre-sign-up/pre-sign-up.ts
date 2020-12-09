// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CognitoUserPoolTriggerHandler } from 'aws-lambda';
import Zk from '@nuid/zk';

export const handler: CognitoUserPoolTriggerHandler = async event => {
    const verifiable = JSON.parse(event.request.validationData.verifiable);

    // Verify the "self-signed" proof in order to verify that a well-formed
    // proof has been generated upfront, prior to continuing with registration
    // or persisting new user data. This isn't strictly necessary but is
    // considered good practice.
    if (!verifiable || !Zk.isVerified(verifiable))
      throw "Invalid request"

    event.response.autoConfirmUser = true;
    return event;
};
