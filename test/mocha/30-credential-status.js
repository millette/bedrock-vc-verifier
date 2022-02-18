/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const bedrock = require('bedrock');
const {CapabilityAgent} = require('@digitalbazaar/webkms-client');
const {documentLoader: brDocLoader} =
  require('bedrock-jsonld-document-loader');
const helpers = require('./helpers');
const {httpClient} = require('@digitalbazaar/http-client');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const express = require('express');
const fs = require('fs');
const https = require('https');
const mockData = require('./mock.data');
const vc = require('@digitalbazaar/vc');
const revocationListCtx = require('vc-revocation-list-context');
const statusListCtx = require('vc-status-list-context');
const {util: {clone}} = bedrock;

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

const VC_SL_CONTEXT_URL = statusListCtx.constants.CONTEXT_URL_V1;
const VC_RL_CONTEXT_URL =
  revocationListCtx.constants.VC_REVOCATION_LIST_CONTEXT_V1_URL;

const encodedList100k =
  'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA';
const encodedList100KWith50KthRevoked =
  'H4sIAAAAAAAAA-3OMQ0AAAgDsOHfNB72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFrc4zDz' +
  'UMAAA';
const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

let slCredential;
let unsignedCredentialSl2021Type;
let revokedSlCredential;
let revokedUnsignedCredential;
let rlCredential;
let unsignedCredentialRL2020Type;
let revokedRlCredential;
let revokedUnsignedCredential2;

// load docs from test server (e.g., load RL VCs and SL VCs)
let testServerBaseUrl;
async function _documentLoader(url) {
  if(url.startsWith(testServerBaseUrl)) {
    const response = await httpClient.get(url, {agent});
    return {
      contextUrl: null,
      documentUrl: url,
      document: response.data
    };
  }
  return brDocLoader(url);
}

function _startServer({app}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(() => {
      const {port} = server.address();
      const BASE_URL = `https://localhost:${port}`;
      testServerBaseUrl = BASE_URL;
      console.log(`Test server listening at ${BASE_URL}`);

      // Status List 2021 Credential
      slCredential = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          VC_SL_CONTEXT_URL
        ],
        id: `${BASE_URL}/status/1`,
        issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
        issuanceDate: '2022-01-10T04:24:12.164Z',
        type: ['VerifiableCredential', 'StatusList2021Credential'],
        credentialSubject: {
          id: `${BASE_URL}/status/1#list`,
          type: 'RevocationList2021',
          encodedList: encodedList100k
        }
      };

      // Unsigned 2021 Credential
      unsignedCredentialSl2021Type = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          VC_SL_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/1#67342`,
          type: 'RevocationList2021Status',
          statusListIndex: '67342',
          statusListCredential: slCredential.id
        },
        issuer: slCredential.issuer,
      };

      // Revoked Status List 2021 Credential
      revokedSlCredential = clone(slCredential);

      revokedSlCredential.id = `${BASE_URL}/status/2`,
      revokedSlCredential.credentialSubject.encodedList =
        encodedList100KWith50KthRevoked;
      revokedSlCredential.credentialSubject.id = `${BASE_URL}/status/2#list`;

      // Revoked Unsigned 2021 Credential
      revokedUnsignedCredential = clone(unsignedCredentialSl2021Type);
      revokedUnsignedCredential.credentialStatus.id =
        `${revokedSlCredential.id}#50000`;
      revokedUnsignedCredential.credentialStatus.statusListIndex = 50000;
      revokedUnsignedCredential.credentialStatus.statusListCredential =
        `${revokedSlCredential.id}`;
      revokedUnsignedCredential.issuer = revokedSlCredential.issuer;

      // Revocation List 2020 Credential
      rlCredential = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          VC_RL_CONTEXT_URL
        ],
        id: `${BASE_URL}/status/3`,
        issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
        issuanceDate: '2022-01-10T04:24:12.164Z',
        type: ['VerifiableCredential', 'RevocationList2020Credential'],
        credentialSubject: {
          id: `${BASE_URL}/status/3#list`,
          type: 'RevocationList2020',
          encodedList: encodedList100k
        }
      };

      // Unsigned 2020 Credential
      unsignedCredentialRL2020Type = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          VC_RL_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        issuanceDate: '2022-01-11T19:23:24Z',
        credentialStatus: {
          id: `${BASE_URL}/status/3#67342`,
          type: 'RevocationList2020Status',
          revocationListIndex: '67342',
          revocationListCredential: rlCredential.id
        },
        issuer: rlCredential.issuer,
      };

      // Revoked Revocation List 2020 Credential
      revokedRlCredential = clone(rlCredential);

      revokedRlCredential.id = `${BASE_URL}/status/4`,
      revokedRlCredential.credentialSubject.encodedList =
        encodedList100KWith50KthRevoked;
      revokedRlCredential.credentialSubject.id = `${BASE_URL}/status/4#list`;

      // Revoked Unsigned 2020 Credential
      revokedUnsignedCredential2 = clone(unsignedCredentialRL2020Type);
      revokedUnsignedCredential2.credentialStatus.id =
        `${revokedRlCredential.id}#50000`;
      revokedUnsignedCredential2.credentialStatus.revocationListIndex = 50000;
      revokedUnsignedCredential2.credentialStatus.revocationListCredential =
        `${revokedRlCredential.id}`;
      revokedUnsignedCredential2.issuer = revokedRlCredential.issuer;

      return resolve(server);
    });
  });
}

const app = express();
app.use(express.json());

// mount the test routes
app.get('/status/1',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid status list 2021 type credential
    res.json(slCredential);
  });
app.get('/status/2',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a revoked status list 2021 type credential
    res.json(revokedSlCredential);
  });
app.get('/status/3',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid revocation list 2020 type credential
    res.json(rlCredential);
  });
app.get('/status/4',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a revoked revocation list 2020 type credential
    res.json(revokedRlCredential);
  });
let server;
before(async () => {
  server = await _startServer({app});
});
after(async () => {
  server.close();
});

describe('verify credential status', () => {
  let keyData;
  let keyPair;
  let suite;
  before(async () => {
    keyData = {
      id: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv#' +
        'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      controller: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      privateKeyMultibase: 'zrv2rP9yjtz3YwCas9m6hnoPxmoqZV72xbCEuomXi4wwSS' +
        '4ShekesADYiAMHoxoqfyBDKQowGMvYx9rp6QGJ7Qbk7Y4'
    };
    keyPair = await Ed25519VerificationKey2020.from(keyData);
    suite = new Ed25519Signature2020({key: keyPair});
  });
  let capabilityAgent;
  let verifierConfig;
  let verifierId;
  let rootZcap;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
      agent
    });

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });

    // create verifier instance
    verifierConfig = await helpers.createConfig({capabilityAgent, zcaps});
    verifierId = verifierConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;
  });
  it('should verify "StatusList2021Credential" type', async () => {
    slCredential = await vc.issue({
      credential: slCredential,
      documentLoader: _documentLoader,
      suite
    });
    const verifiableCredential = await vc.issue({
      credential: unsignedCredentialSl2021Type,
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    const [r] = result.data.results;
    r.verified.should.be.a('boolean');
    r.verified.should.equal(true);
  });
  it('should fail to verify a revoked "StatusList2021Credential" type',
    async () => {
      revokedSlCredential = await vc.issue({
        credential: revokedSlCredential,
        documentLoader: _documentLoader,
        suite
      });
      const verifiableCredential = await vc.issue({
        credential: revokedUnsignedCredential,
        documentLoader: _documentLoader,
        suite
      });
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/credentials/verify`,
          capability: rootZcap,
          json: {
            options: {
              checks: ['credentialStatus'],
            },
            verifiableCredential
          }
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      const {checks, error: {message: errorMsg}} = error.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      errorMsg.should.equal('The credential failed a status check.');
      error.data.statusResult.verified.should.equal(false);
      const [{check}] = checks;
      check.should.be.an('array');
      check.should.eql(['credentialStatus']);
      should.exist(error.data.results);
      error.data.results.should.be.an('array');
      error.data.results.should.have.length(1);
      const [r] = error.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    });
  it('should verify "RevocationList2020Credential" type', async () => {
    rlCredential = await vc.issue({
      credential: rlCredential,
      documentLoader: _documentLoader,
      suite
    });
    const verifiableCredential = await vc.issue({
      credential: unsignedCredentialRL2020Type,
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    const [r] = result.data.results;
    r.verified.should.be.a('boolean');
    r.verified.should.equal(true);
  });
  it('should fail to verify a revoked "RevocationList2020Credential" type',
    async () => {
      revokedRlCredential = await vc.issue({
        credential: revokedRlCredential,
        documentLoader: _documentLoader,
        suite
      });
      const verifiableCredential = await vc.issue({
        credential: revokedUnsignedCredential2,
        documentLoader: _documentLoader,
        suite
      });
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/credentials/verify`,
          capability: rootZcap,
          json: {
            options: {
              checks: ['credentialStatus'],
            },
            verifiableCredential
          }
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      const {checks, error: {message: errorMsg}} = error.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      errorMsg.should.equal('The credential failed a status check.');
      error.data.statusResult.verified.should.equal(false);
      const [{check}] = checks;
      check.should.be.an('array');
      check.should.eql(['credentialStatus']);
      should.exist(error.data.results);
      error.data.results.should.be.an('array');
      error.data.results.should.have.length(1);
      const [r] = error.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    });
});
