/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const base58universal = require('base58-universal');
const bedrock = require('bedrock');
const {didIo} = require('bedrock-did-io');
const {
  documentLoader: bedrockLoader
} = require('bedrock-jsonld-document-loader');
const {hexToBin, instantiateSecp256k1} = require('bitcoin-ts');
const {httpClient} = require('@digitalbazaar/http-client');
const jsonld = require('jsonld');
const keyto = require('@trust/keyto');
const {constants: {DID_CONTEXT_URL}} = require('did-context');
const {constants: {VERES_ONE_CONTEXT_V1_URL}} = require('veres-one-context');

const JWS_2020_CONTEXT_URL = 'https://w3id.org/security/suites/jws-2020/v1';
const SECP256K1_2019_CONTEXT_URL =
  'https://w3id.org/security/suites/secp256k1-2019/v1';

const {config} = bedrock;

const api = {};

module.exports = api;

bedrock.events.on('bedrock.start', () => {
  const {'vc-verifier': cfg} = config;
  api.loaders.push(bedrockLoader);
  // FIXME: use computed config API instead of eventing this
  api.loaders.push(_didLoader);
  // FIXME: configure using did-io
  api.loaders.push(_didEbsiLoader);
  // if enabled, add loader for remote documents
  if(cfg.documentLoader.mode === 'web') {
    api.loaders.push(_webLoader);
  }
});

api.documents = new Map();

api.documentLoader = async url => {
  let result;

  for(const loader of api.loaders) {
    try {
      result = await loader(url);
    } catch(e) {
      // this loader failed move on to the next
      continue;
    }
    if(result) {
      return result;
    }
  }
  // failure, throw
  throw new Error(`Document not found: ${url}`);
};

// delimiters for a DID URL
const splitRegex = /[;\/\?#]/;
// this loader is intended for dids
api.documentCache = async url => {
  if(!url.startsWith('did:')) {
    throw new Error('NotFoundError');
  }
  const [did] = url.split(splitRegex);
  let didDocument;
  if(api.documents.has(did)) {
    didDocument = bedrock.util.clone(api.documents.get(did));
  } else {
    throw new Error('NotFoundError');
  }
  if(!url.includes('#')) {
    return {
      contextUrl: null,
      document: didDocument,
      documentUrl: url
    };
  }
  // try to find the specific object in the DID document
  const context = [DID_CONTEXT_URL];
  if(url.startsWith('did:v1:')) {
    context.push(VERES_ONE_CONTEXT_V1_URL);
  }

  const document = await _pluckDidNode(url, didDocument, context);
  return {
    contextUrl: null,
    document,
    documentUrl: url
  };
};

api.loaders = [api.documentCache];

async function _didLoader(url) {
  if(!url.startsWith('did:')) {
    throw new Error('NotFoundError');
  }
  let document;
  try {
    document = await didIo.get({did: url});
  } catch(e) {
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    documentUrl: url,
    document
  };
}

async function _didEbsiLoader(url) {
  if(!url.startsWith('did:ebsi:')) {
    throw new Error('NotFoundError');
  }

  const [did, fragment] = url.split('#');
  let document;
  try {
    const ebsiUrl = 'https://api.preprod.ebsi.eu/did-registry/v2/identifiers/';
    // TODO: Notify EBSI that this should be encodeURIComponent(did)
    const result = await httpClient.get(`${ebsiUrl}${did}`, {agent});
    const didDocument = result.data;

    // ensure context is an array
    if(!didDocument['@context']) {
      didDocument['@context'] = [];
    } else if(!Array.isArray(didDocument['@context'])) {
      didDocument['@context'] = [didDocument['@context']];
    }

    // DID Doc contains JWS2020 Keys, add missing JWS 2020 Context
    didDocument['@context'].push(JWS_2020_CONTEXT_URL);
    document = didDocument;

    if(fragment) {
      // pluck node from DID Doc based on context below
      const context = [DID_CONTEXT_URL, JWS_2020_CONTEXT_URL];
      document = await _pluckDidNode(url, didDocument, context);

      // translate JsonWebKey2020 to EcdsaSecp256k1VerificationKey2019 if it
      // is the current document (key) that we're processing
      const {type, publicKeyJwk} = document;
      if(type === 'JsonWebKey2020' && publicKeyJwk.crv === 'secp256k1') {
        document = await _translateJwk2020ToSecp2561VerificationKey({
          did, jwk2020: document});
      }
    }
  } catch(e) {
    console.error(e);
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    documentUrl: url,
    document
  };
}

async function _pluckDidNode(target, didDocument, context) {
  // flatten to isolate target
  const flattened = await jsonld.flatten(didDocument);
  // filter out non-DID nodes and find target
  let found = false;
  const filtered = [];
  for(const node of flattened) {
    const id = node['@id'];
    if(id === target) {
      filtered.push(node);
      found = true;
      break;
    }
  }
  // target not found
  if(!found) {
    const err = new Error('Not Found');
    err.httpStatusCode = 404;
    err.status = 404;
    throw err;
  }

  // frame target
  const framed = await jsonld.frame(
    filtered, {'@context': context, id: target}, {embed: '@always'});
  return Object.assign({'@context': context}, framed);
}

async function _webLoader(url) {
  if(!url.startsWith('http')) {
    throw new Error('NotFoundError');
  }
  let result;
  try {
    result = await httpClient.get(url, {agent});
  } catch(e) {
    throw new Error('NotFoundError');
  }

  return {
    contextUrl: null,
    document: result.data,
    documentUrl: url
  };
}

async function _translateJwk2020ToSecp2561VerificationKey({did, jwk2020}) {
  const {id, publicKeyJwk} = jwk2020;

  const uncompressedPublicKey = keyto.from(
    {...publicKeyJwk, crv: 'K-256'}, 'jwk').toString('blk', 'public');
  const secp256k1 = await instantiateSecp256k1();
  const compressed = secp256k1.compressPublicKey(
    hexToBin(uncompressedPublicKey));

  return {
    '@context': [DID_CONTEXT_URL, SECP256K1_2019_CONTEXT_URL],
    id,
    type: 'EcdsaSecp256k1VerificationKey2019',
    // add controller manually because it did not exist in original JWK2020
    controller: did,
    publicKeyBase58: base58universal.encode(compressed)
  };
}
