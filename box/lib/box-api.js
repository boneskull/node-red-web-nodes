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

// note the confusing naming
const BoxSDKNode = require('box-node-sdk');

module.exports = RED => {

    /**
     * Consumes a readable stream as a UTF-8 string;
     * resolves Promise when stream ends.
     * @param {ReadableStream} stream 
     * @returns Promise<string> Stream data
     */
    const streamToPromise = stream => {
        let content = '';
        return new Promise((resolve, reject) => {
            stream.on('data', chunk => {
                    content += chunk;
                })
                .on('end', () => {
                    resolve(content);
                })
                .on('error', err => {
                    reject(err);
                });
        });
    };

    const normalizeFilepath = filepath =>
        (typeof filepath === "string" ? filepath.split("/").filter(Boolean) : filepath.filter(Boolean));

    /**
     * Provides an adapter for a Box SDK persistent client to store its tokens
     * in Node-RED.
     * For our purposes, this is the entirety of the Node's `credentials` object.
     * This class is *not* used directly by the Nodes.
     */
    class TokenStore {
        /**
         * Assigns this TokenStore a Node ID
         * @param {string} id Node ID to associate TokenStore with
         */
        constructor(id) {
            this.id = id;
        }

        /**
         * Reads the token store
         * @param {Function} cb Nodeback
         */
        read(cb) {
            const id = this.id;
            // this is only here to force the callback to be called async
            process.nextTick(() => {
                cb(null, RED.nodes.getCredentials(id));
            });
        }

        /**
         * Writes "Token Info" to the token store
         * @param {Object} tokenInfo "Token Info" object
         * @param {Function} cb Nodeback
         */
        write(tokenInfo, cb) {
            const id = this.id;
            const credentials = RED.nodes.getCredentials(id);
            Object.assign(credentials, tokenInfo);
            RED.nodes.addCredentials(id, credentials)
                .then(() => cb(), cb);
        }

        /**
         * Annihilates the contents of the token store
         * @param {Function} cb Nodeback
         */
        clear(cb) {
            this.write(null, cb);
        }
    }

    /**
     * Collection of mixins for difft behavior of difft auth strategies.
     */
    const AuthModeMixins = {
        OAUTH2: {
            /**
             * `true` if the credentials are in place 
             * @this BoxCredentialsNode
             * @returns {boolean} Credentials OK
             */
            _hasCredentials() {
                const c = this.credentials;
                return c.privateKey && c.clientSecret && c.clientId && c.accessToken &&
                    c.refreshToken && c.accessTokenTTLMS && c.acquiredAtMS;
            },

            /**
             * A Box SDK client, created as per the auth mode.
             * @returns {BoxClient}
             */
            _client() {
                if (this.__client) {
                    return this.__client;
                }
                return this.sdk.getPersistentClient({
                    accessToken: this.credentials.accessToken,
                    refreshToken: this.credentials.refreshToken,
                    acquiredAtMS: this.credentials.acquiredAtMS,
                    accessTokenTTLMS: this.credentials.accessTokenTTLMS
                }, this.tokenStore);
            },

            /**
             * A Box SDK instance, created as per the auth mode.
             * @returns {BoxSDKNode}
             */
            _sdk() {
                if (this.__sdk) {
                    return this.__sdk;
                }
                this.__sdk = new BoxSDKNode({
                    clientID: this.credentials.clientId,
                    clientSecret: this.credentials.clientSecret
                });
                return this.__sdk;
            },

            /**
             * Gets an event stream
             * @param {Object} [options={}] Options
             * @param {number} [options.interval=0] Fetch interval, in seconds
             * @returns {Promise<EventStream>} Readable stream
             */
            eventStream(options) {
                return this.client.events.getEventStream({
                    // this is milliseconds.  handy!
                    fetchInterval: (options.interval || 0) * 1000
                });
            }
        },
        APP: {
            /**
             * `true` if the credentials are in place 
             * @this BoxCredentialsNode
             * @returns {boolean} Credentials OK
             */
            _hasCredentials() {
                const c = this.credentials;
                return c.clientId && c.clientSecret && c.publicKeyId && c.privateKey &&
                    c.passphrase && c.appEnterpriseId;
            },
            /**
             * A Box SDK client, created as per the app mode.
             * If `appUserId` is present, return an "app user" client; otherwise
             * an enterprise one.
             * @returns {BoxClient}
             */
            _client() {
                if (this.__client) {
                    return this.__client;
                }

                if (this.credentials.appUserId) {
                    this.__client = this.sdk.getAppAuthClient('user', this.credentials.appUserId);
                    this.debug(`Authenticating as app user ${this.credentials.appUserId}`);
                } else {
                    this.__client = this.sdk.getAppAuthClient('enterprise', this.credentials.appEnterpriseId);
                    this.debug('Authenticating as service user');
                }

                return this.__client;
            },

            /**
             * A Box SDK instance, created as per the app mode
             * @returns {BoxSDKNode}
             */
            _sdk() {
                if (this.__sdk) {
                    return this.__sdk;
                }
                this.__sdk = new BoxSDKNode({
                    clientID: this.credentials.clientId,
                    clientSecret: this.credentials.clientSecret,
                    appAuth: {
                        keyID: this.credentials.publicKeyId,
                        privateKey: this.credentials.privateKey,
                        passphrase: this.credentials.passphrase
                    }
                });
                return this.__sdk;
            },

            /**
             * Gets an enterprise event stream
             * @param {Object} [options={}] Options
             * @param {number} [options.interval=0] Polling interval, in seconds
             * @returns {Promise<EnterpriseEventStream>} Readable stream
             */
            eventStream(options) {
                return this.credentials.appUserId ? AuthModeMixins.OAUTH2.eventStream.call(this, options) :
                    this.client.events.getEnterpriseEventStream({
                        // this is seconds
                        pollingInterval: options.interval
                    });
            }
        },
        DEV: {
            /**
             * `true` if the credentials are in place 
             * @this BoxCredentialsNode
             * @returns {boolean} Credentials OK
             */
            _hasCredentials() {
                const c = this.credentials;
                return c.clientId && c.clientSecret && c.devToken;
            },

            /**
             * @returns {BoxClient}
             */
            _client() {
                return this.sdk.getBasicClient(this.credentials.devToken);
            },

            /**
             * @returns {BoxSDKNode}
             */
            _sdk() {
                return AuthModeMixins.OAUTH2._sdk.call(this);
            },

            eventStream() {
                throw new Error('not implemented');
            }
        }
    };

    /**
     * Represents an interface into the Box API; contains credentials.
     * Requires a mixin applied from `AuthModeMixins` to work properly;
     * the `authMode` property determines this.
     */
    class BoxAPINode {
        constructor(n) {
            RED.nodes.createNode(this, n);

            /**
             * @memberof BoxAPINode
             * @type string
             */
            this.authMode = n.authMode || 'OAUTH2';

            if (!AuthModeMixins[this.authMode]) {
                this.error('Invalid auth mode');
                return;
            }

            Object.assign(this, AuthModeMixins[this.authMode]);
        }

        /**
         * The TokenStore associated with this Node
         * @type TokenStore
         */
        get tokenStore() {
            const tokenStore = this._tokenStore;
            if (tokenStore) {
                return tokenStore;
            }
            this._tokenStore = new TokenStore(this.id);
            return this.tokenStore;
        }

        /**
         * @type BoxSDKNode
         */
        get sdk() {
            return this._sdk();
        }

        /**
         * @type BoxClient
         */
        get client() {
            return this._client();
        }

        /**
         * @type boolean
         */
        get hasCredentials() {
            return this._hasCredentials();
        }

        /**
         * Returns the ID of a filepath's containing folder in Box
         * @param {string} filepath A filepath
         * @param {string} [folderId=0] Parent folder ID; defaults to root
         * @returns {Promise<string>} A folder ID
         */
        resolvePath(filepath, folderId) {
            return Promise.resolve()
                .then(() => {
                    folderId = folderId || '0';
                    filepath = normalizeFilepath(filepath);
                    if (!filepath.length) {
                        return folderId;
                    }
                    const folder = filepath.shift();
                    return this.client.folders.getItems(folderId)
                        .then(data => {
                            const entries = data.entries;
                            for (let i = 0; i < entries.length; i++) {
                                if (entries[i].type === 'folder' &&
                                    entries[i].name === folder) {
                                    // found
                                    return this.resolvePath(filepath, entries[i].id);
                                }
                            }
                            return Promise.reject(RED._("box.error.not-found"));
                        });
                });
        }

        /**
         * Attaches a listener function to an event stream
         * @param {Function} listener Listener function; receives event object
         * @param {Object} [options={}] Options
         * @param {number} [options.interval=0] Polling or fetch interval, in seconds
         * @returns {Promise<Function>} An "unsubscribe" function
         */
        subscribe(listener, options) {
            options = options || {};
            return this.eventStream(options)
                .then(stream => {
                    stream.on('error', err => {
                            this.error(RED._('box.error.event-fetch-failed', {
                                err: err.toString()
                            }));
                        })
                        .on('data', listener);

                    this.on('close', () => {
                        stream.removeAllListeners('data')
                            .removeAllListeners('error');
                    });

                    return () => {
                        stream.removeListener('data', listener);
                    };
                });
        }

        /**
         * Finds a file's ID by filename
         * @param {string} filename A filename
         * @returns {Promise<string>} File ID, if found
         */
        resolveFile(filename) {
            return Promise.resolve()
                .then(() => {
                    filename = normalizeFilepath(filename);
                    if (!filename.length) {
                        return Promise.reject(RED._("box.error.missing-filename"));
                    }
                    const file = filename.pop();
                    return this.resolvePath(filename)
                        .then(id => this.client.folders.getItems(id))
                        .then(data => {
                            const entries = data.entries;
                            for (var i = 0; i < entries.length; i++) {
                                if (entries[i].type === 'file' &&
                                    entries[i].name === file) {
                                    // found
                                    return entries[i].id;
                                }
                            }
                            return Promise.reject(RED._("box.error.not-found"));
                        });
                });
        }

        /**
         * Downloads a file, optionally coerced to a representation type.
         * @param {string} filepath A filepath
         * @param {FileRepresentationType} [representation] File representation type
         * @returns {Promise<Buffer|string>} A Buffer or string of the file contents (or representation thereof)
         */
        download(filepath, representation) {
            return Promise.resolve()
                .then(() => {
                    if (representation && this.client.files.representation[representation]) {
                        return this.client.files.getRepresentationContent(
                            filepath, this.client.files.representation[representation]
                        );
                    }
                    // "raw"
                    return this.client.files.getReadStream(filepath);
                })
                .then(streamToPromise);
        }

        /**
         * @todo
         */
        upload() {
            throw new Error('not implemented');
        }
    }

    RED.nodes.registerType("box-credentials", BoxAPINode, {
        credentials: {
            displayName: {
                type: "text"
            },
            clientId: {
                type: "text"
            },
            clientSecret: {
                type: "password"
            },
            accessToken: {
                type: "password"
            },
            refreshToken: {
                type: "password"
            },
            accessTokenTTLMS: {
                type: "text"
            },
            acquiredAtMS: {
                type: 'text'
            },
            publicKeyId: {
                type: 'text'
            },
            privateKey: {
                type: 'password'
            },
            passphrase: {
                type: 'password'
            },
            appEnterpriseId: {
                type: 'text'
            },
            appUserId: {
                type: 'text'
            }
        }
    });
};
