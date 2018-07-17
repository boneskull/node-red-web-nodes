/**
 * Copyright 2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

 'use strict';

const crypto = require('crypto');
const url = require('url');

module.exports = RED => {

  RED.httpAdmin.get('/box-credentials/auth', (req, res) => {
      if (!req.query.clientId || !req.query.clientSecret ||
          !req.query.id || !req.query.callback) {
          res.send(400);
          return;
      }
      const nodeId = req.query.id;
      const callback = req.query.callback;
      const credentials = {
          clientId: req.query.clientId,
          clientSecret: req.query.clientSecret
      };

      const csrfToken = crypto.randomBytes(18)
          .toString('base64')
          .replace(/\//g, '-')
          .replace(/\+/g, '_');
      credentials.csrfToken = csrfToken;
      credentials.callback = callback;
      res.cookie('csrf', csrfToken);
      res.redirect(url.format({
          protocol: 'https',
          hostname: 'app.box.com',
          pathname: '/api/oauth2/authorize',
          query: {
              response_type: 'code',
              client_id: credentials.clientId,
              state: nodeId + ":" + csrfToken,
              redirect_uri: callback
          }
      }));
      RED.nodes.addCredentials(nodeId, credentials);
  });

  RED.httpAdmin.get('/box-credentials/auth/callback', (req, res) => {
      if (req.query.error) {
          return res.send('ERROR: ' + req.query.error + ': ' + req.query.error_description);
      }
      const state = req.query.state.split(':');
      const nodeId = state[0];
      const credentials = RED.nodes.getCredentials(nodeId);
      if (!credentials || !credentials.clientId || !credentials.clientSecret) {
          return res.send(RED._("box.error.no-credentials"));
      }
      if (state[1] !== credentials.csrfToken) {
          return res.status(401).send(
              RED._("box.error.token-mismatch")
          );
      }

      const sdk = new BoxSDK({
          clientID: credentials.clientId,
          clientSecret: credentials.clientSecret
      });

      sdk.getTokensAuthorizationCodeGrant(req.query.code)
          .then(tokenInfo => {
              const tokenStore = new TokenStore(nodeId);
              return new Promise((resolve, reject) => {
                  tokenStore.write(tokenInfo, err => {
                      if (err) {
                          return reject(err);
                      }
                      resolve({
                          tokenStore: tokenStore,
                          tokenInfo: tokenInfo
                      });
                  });
              });
          })
          .then(data => {
              const tokenInfo = data.tokenInfo;
              const tokenStore = data.tokenStore;
              const client = sdk.getPersistentClient(tokenInfo, tokenStore);
              return client.users.get(client.CURRENT_USER_ID);
          })
          .then(user => {
              credentials.displayName = user.name;
              RED.nodes.addCredentials(nodeId, credentials);
              res.send(RED._("box.error.authorized"));
          })
          .catch(err => {
              res.status(500).send(err.toString());
          });
  });

};
