// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { Injectable, Inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { Auth } from 'aws-amplify';
import { CognitoUser, CognitoUserAttribute } from 'amazon-cognito-identity-js';
import Zk from '@nuid/zk';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private cognitoUser: CognitoUser & { challengeParam: { email: string, challenge: string } };

  // Get access to window object in the Angular way
  private window: Window;
  constructor(@Inject(DOCUMENT) private document: Document) {
    this.window = this.document.defaultView;
  }

  public async signIn(email: string) {
    this.cognitoUser = await Auth.signIn(email);
  }

  public async signOut() {
    await Auth.signOut();
  }

  public async answerCustomChallenge(proof: object) {
    this.cognitoUser = await Auth.sendCustomChallengeAnswer(
      this.cognitoUser,
      JSON.stringify(proof)
    );

    return this.isAuthenticated();
  }

  public async getPublicChallengeParameters() {
    return this.cognitoUser.challengeParam;
  }

  public async signUp(email: string, fullName: string, password: string) {
    const verifiable = Zk.verifiableFromSecret(password);
    const credential = Zk.credentialFromVerifiable(verifiable);

    // The parameters to `Auth.signUp` include
    // `custom:credential` — The public, non-sensitive data that will be
    //     persisted for subsequent authentication attempts. In this example,
    //     this data is persisted directly in the Cognito UserPool, which works
    //     great and can be extremely convenient. Using a public credential
    //     store allows identities to be independently verified by
    //     authenticating services. See `cognito/template.yaml` for UserPool
    //     configuration of this UserAttribute.
    // `validationData.verifiable` — A "self-signed" verifiable proof for the
    //     `pre-sign-up` lambda trigger to verify upon initial registration.
    //     This ensures that the user has generated a well-formed proof upfront.
    const params = {
      username: email,
      password: this.getRandomString(30),
      attributes: {
        name: fullName,
        'custom:credential': JSON.stringify(credential)
      },
      validationData: [
        new CognitoUserAttribute({
          Name: 'verifiable',
          Value: JSON.stringify(verifiable)
        })
      ]
    };
    await Auth.signUp(params);
  }

  public async getChallenge() {
    const { challenge } = await this.getPublicChallengeParameters();
    return JSON.parse(challenge);
  }

  public async logIn(email: string, password: string) {
    await this.signIn(email);
    const challenge = await this.getChallenge();
    const proof = Zk.proofFromSecretAndChallenge(password, challenge);

    // Log in using a single-use zero knowledge proof. The
    // `verify-auth-challenge-response` lambda trigger will combine the one-time
    // proof with the unique challenge generated in `create-auth-challenge` and
    // stored in the event's `privateChallengeParameters`. Based on this
    // combination, `verify-auth-challenge-response` will accept or deny the
    // login attempt. `privateChallengeParameters` could also be used to further
    // constrain the context of the authentication attempt, e.g. binding the
    // challenge to a certain point in time and only accepting proofs generated
    // from that challenge prior to some later time.
    return await this.answerCustomChallenge(proof);
  }

  private getRandomString(bytes: number) {
    const randomValues = new Uint8Array(bytes);
    this.window.crypto.getRandomValues(randomValues);
    return Array.from(randomValues).map(this.intToHex).join('');
  }

  private intToHex(nr: number) {
    return nr.toString(16).padStart(2, '0');
  }

  public async isAuthenticated() {
    try {
      await Auth.currentSession();
      return true;
    } catch {
      return false;
    }
  }

  public async getUserDetails() {
    if (!this.cognitoUser) {
      this.cognitoUser = await Auth.currentAuthenticatedUser();
    }
    return await Auth.userAttributes(this.cognitoUser);
  }

}
