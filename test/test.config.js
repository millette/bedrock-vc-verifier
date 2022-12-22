/*!
 * Copyright (c) 2012-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {agent} from '@bedrock/https-agent';
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/app-identity';
import '@bedrock/https-agent';
import '@bedrock/mongodb';
import '@bedrock/service-agent';
import '@bedrock/vc-verifier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.mocha.options.fullTrace = true;
config.mocha.tests.push(path.join(__dirname, 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_vc_verifier_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// create test application identity
// ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-verifier'] = {
  id: 'did:key:z6MkrH839XwPCUQ2TkA6ifehciWnEvzuQ2njc6J19fpuP5oN',
  seedMultibase: 'z1AgvAGfbairK3AV6GqbeF8gSpYZXftQsGb5DTjptgawNyn',
  serviceType: 'vc-verifier'
};

// use local KMS for testing
config['service-agent'].kms.baseUrl = 'https://localhost:18443/kms';
config['vc-verifier'].methods.web.fetchOptions = {agent};
// set up express to set did:web didDocuments
config.express.static.push({route: '/test/dids', path: './.well-known'});
