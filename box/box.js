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


module.exports = function(RED) {
    "use strict";
    var crypto = require("crypto");
    var fs = require("fs");
    var url = require("url");
    var minimatch = require("minimatch");
    const BoxSDK = require('box-node-sdk');
    
    const AUTH_MODE_OAUTH2 = 'OAUTH2';
    const AUTH_MODE_APP = 'APP';
    const AUTH_MODE_DEV = 'DEV';

    function normalizeFilepath (filepath) {
        return (typeof filepath === "string" ? filepath.split("/").filter(Boolean) : filepath.filter(Boolean));
    }

    function streamToPromise (stream) {
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
    }

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
  
    class BoxCredentialsNode {
        constructor(n) {
            RED.nodes.createNode(this,n);

            this.authMode = n.authMode || AUTH_MODE_OAUTH2;

            // if we have an active event stream, remove the "error" listener, which
            // would have been set in BoxCredentialsNode#getEventStream.
            this.on('close', () => {
                if (this._eventStream) {
                    // ideally, nothing else should be listening for errors here.
                    this._eventStream.removeAllListeners('error');
                }
            });
        }

        /**
         * `true` if the credentials are in place per the auth mode.
         * @type Boolean
         */
        get hasCredentials () {
            switch (this.authMode) {
                case AUTH_MODE_OAUTH2:
                    return Boolean(this.credentials.accessToken);
                case AUTH_MODE_APP: 
                    return Boolean(this.credentials.privateKey);
                case AUTH_MODE_DEV:
                    return Boolean(this.credentials.devToken);
                default:
                    return false;
            }
        }

        /**
         * The TokenStore associated with this Node
         * @type TokenStore
         */
        get tokenStore () {
            const tokenStore = this._tokenStore;
            if (tokenStore) {
                return tokenStore;
            }
            this._tokenStore = new TokenStore(this.id);
            return this.tokenStore;
        }

        /**
         * A Box SDK client, created as per the auth mode.
         * @type BoxClient
         */
        get client () {
            if (this._client) {
                return this._client;
            }
            const sdk = this.sdk;
            if (this.authMode === AUTH_MODE_OAUTH2) {
                return sdk.getPersistentClient({
                    accessToken: this.credentials.accessToken,
                    refreshToken: this.credentials.refreshToken,
                    acquiredAtMS: this.credentials.acquiredAtMS,
                    accessTokenTTLMS: this.credentials.accessTokenTTLMS
                }, this.tokenStore);
            }
            if (this.credentials.appEnterpriseId) {
                return sdk.getAppAuthClient(
                    'enterprise', this.credentials.appEnterpriseId
                );
            }
            return sdk.getAppAuthClient('user', this.credentials.appUserId);
        }

        /**
         * A Box SDK instance, created as per the auth mode.
         * @type BoxSDKNode
         */
        get sdk () {
            if (this._sdk) {
                return this._sdk;
            }
            this._sdk = new BoxSDK(
                this.authMode === AUTH_MODE_APP ? {
                    clientID: this.credentials.clientId,
                    clientSecret: this.credentials.clientSecret,
                    appAuth: {
                        keyID: this.credentials.publicKeyId,
                        privateKey: this.credentials.privateKey,
                        passphrase: this.credentials.passphrase
                    }
                } : {
                    clientID: this.credentials.clientId,
                    clientSecret: this.credentials.clientSecret
                }
            );
            return this._sdk;
        }

        /**
         * Gets folder info from Box
         * @param {string} id Folder ID
         * @returns {Promise<Object>} Folder info
         */
        folderInfo (id) {
            return this.client.folders.get(id);
        }

        folderItems (id) {
            return this.client.folders.getItems(id);
        }

        /**
         * Gets an event stream from Box, as per the auth mode
         * @param {Object} [options={}] Options
         * @param {number} [options.interval=0] Polling or fetch interval, in seconds
         * @private
         * @returns {Promise<EventStream|EnterpriseEventStream>} A Readable stream
         */
        getEventStream (options) {
            options = options || {};
            return Promise.resolve()
                .then(() => {
                    if (this._eventStream) {
                        return this._eventStream;
                    }
                    if (this.authMode === AUTH_MODE_APP) {
                        return this.client.events.getEnterpriseEventStream({
                            // this is seconds
                            pollingInterval: options.interval
                        });
                    }
                    return this.client.events.getEventStream({
                        // this is milliseconds.  handy!
                        fetchInterval: (options.interval || 0) * 1000
                    });
                })
                .then(stream => {
                    stream.on('error', err => {
                        this.error(RED._('box.error.event-fetch-failed', {
                            err: err.toString()
                        }));
                    });
                    this._eventStream = stream;
                    return stream;
                });
        }

        /**
         * Returns the ID of a filepath's containing folder in Box
         * @param {string} filepath A filepath
         * @param {string} [folderId=0] Parent folder ID; defaults to root
         * @returns {Promise<string>} A folder ID
         */
        resolvePath (filepath, folderId) {
            return Promise.resolve()
                .then(() => {
                    folderId = folderId || '0';
                    filepath = normalizeFilepath(filepath);
                    if (!filepath.length) {
                        return folderId;
                    }
                    const folder = filepath.shift();
                    return this.folderItems(folderId)
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
        subscribe (listener, options) {
            return this.getEventStream(options)
                .then(stream => {
                    stream.on('data', listener);
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
        resolveFile (filename) {
            return Promise.resolve()
                .then(() => {
                    filename = normalizeFilepath(filename);
                    if (!filename.length) {
                        return Promise.reject(RED._("box.error.missing-filename"));
                    }
                    const file = filename.pop();
                    return this.resolvePath(filename)
                        .then(id => this.folderItems(id))
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
        download (filepath, representation) {
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
    }

    RED.nodes.registerType("box-credentials", BoxCredentialsNode, {
        credentials: {
            displayName: {type:"text"},
            clientId: {type:"text"},
            clientSecret: {type:"password"},
            accessToken: {type:"password"},
            refreshToken: {type:"password"},
            accessTokenTTLMS: {type:"text"},
            acquiredAtMS: {type: 'text'},
            publicKeyId: {type: 'text'},
            privateKey: {type: 'password'},
            passphrase: {type: 'password'},
            appEnterpriseId: {type: 'text'},
            appUserId: {type: 'text'}
        }
    });

    function constructFullPath(entry) {
        if (entry.path_collection) {
            const parentPath = entry.path_collection.entries
                .filter(e => e.id !== "0")
                .map(e => e.name)
                .join('/');
            return (parentPath ? `${parentPath}/` : "") + entry.name;
        }
        return entry.name;
    }

    RED.httpAdmin.get('/box-credentials/auth', function(req, res) {
        if (!req.query.clientId || !req.query.clientSecret ||
            !req.query.id || !req.query.callback) {
            res.send(400);
            return;
        }
        var node_id = req.query.id;
        var callback = req.query.callback;
        var credentials = {
            clientId: req.query.clientId,
            clientSecret: req.query.clientSecret
        };

        var csrfToken = crypto.randomBytes(18)
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
                state: node_id + ":" + csrfToken,
                redirect_uri: callback
            }
        }));
        RED.nodes.addCredentials(node_id, credentials);
    });

    RED.httpAdmin.get('/box-credentials/auth/callback', function(req, res) {
        if (req.query.error) {
            return res.send('ERROR: '+ req.query.error + ': ' + req.query.error_description);
        }
        var state = req.query.state.split(':');
        var node_id = state[0];
        var credentials = RED.nodes.getCredentials(node_id);
        if (!credentials || !credentials.clientId || !credentials.clientSecret) {
            return res.send(RED._("box.error.no-credentials"));
        }
        if (state[1] !== credentials.csrfToken) {
            return res.status(401).send(
                RED._("box.error.token-mismatch")
            );
        }

        var sdk = new BoxSDK({
            clientID: credentials.clientId,
            clientSecret: credentials.clientSecret
        });

        sdk.getTokensAuthorizationCodeGrant(req.query.code)
            .then(tokenInfo => {
                const tokenStore = new TokenStore(node_id);
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
                RED.nodes.addCredentials(node_id, credentials);
                res.send(RED._("box.error.authorized"));
            })
            .catch(err => {
                res.status(500).send(err.toString());
            });
    });

    class BoxEventNode {
        constructor(n) {
            RED.nodes.createNode(this,n);
            this.filepattern = n.filepattern || "";
            this.interval = n.interval || "";
            /**
             * @type BoxCredentialsNode
             **/
            this.box = RED.nodes.getNode(n.box);

            if (!this.box || !this.box.hasCredentials) {
                this.warn(RED._("box.warn.missing-credentials"));
                return;
            }

            this.status({
                fill: "blue",
                shape: "dot",
                text: "box.status.initializing"
            });
            
            this.box.subscribe(event => {
                // if there's a "source" property, we can filter
                if (event.source) {
                    event.fullPath = constructFullPath(event.source);
                    if (this.filepattern && !minimatch(event.fullPath, this.filepattern)) {
                        this.debug(RED._('box.debug.filtered'), {
                            fullPath: event.fullPath,
                            filepattern: this.filepattern
                        });
                        return;
                    }
                }
                this.send({payload: event});
            }, {interval: this.interval})
                .then(unsubscribe => {
                    this.status({
                        fill: 'green',
                        shape: 'circle',
                        text: 'box.status.listening'
                    });
                    this.on('close', unsubscribe);
                })
                .catch(err => {
                    this.error(RED._('box.error.event-stream-initialize-failed', {
                        err: err.toString()
                    }));
                });
        }

        lookupOldPath (msg, entry, event) {
            return Promise.resolve()
                .then(() => {
                    const source = entry.source;
                    this.status({
                        fill: "blue",
                        shape: "dot",
                        text: "box.status.resolving-path"
                    });
                    return this.box.folderInfo(source.parent.id);
                })
                .then(folder => {
                    this.status({});
                    const parentPath = constructFullPath(folder);
                    this.sendEvent(msg, entry, event, (parentPath ? `${parentPath}/` : '') + source.name);
                })
                .catch(err => {
                    this.warn(RED._(
                        "box.warn.old-path-failed", {
                            err: err.toString()
                        }
                    ));
                    this.status({
                        fill: "red",
                        shape: "ring",
                        text: "box.status.failed"
                    });
                })
                // TODO: add folder path_collection to entry.parent?
        }
    }    
    RED.nodes.registerType("box in", BoxEventNode);

    const DOWNLOAD_AS_RAW = 'RAW';

    class BoxDownloadNode {
        constructor (n) {
            RED.nodes.createNode(this,n);
            this.filename = n.filename || "";
            this.downloadAs = n.downloadAs || DOWNLOAD_AS_RAW;
            /**
             * @type BoxCredentialsNode
             */
            this.box = RED.nodes.getNode(n.box);
            if (!this.box || !this.box.hasCredentials) {
                this.warn(RED._("box.warn.missing-credentials"));
                return;
            }

            this.on("input", msg => {
                const filename = this.filename || msg.filename;
                const downloadAs = this.downloadAs || msg.downloadAs;
                if (!filename) {
                    this.error(RED._("box.error.no-filename-specified"));
                    return;
                }
                msg.filename = filename;
                msg.downloadAs = downloadAs;
                this.status({
                    fill: "blue",
                    shape: "dot",
                    text: "box.status.resolving-path"
                });

                this.box.resolveFile(filename)
                    .then(file_id => {
                        this.status({fill:"blue",shape:"dot",text:"box.status.downloading"});
                        return this.box.download(file_id, downloadAs)
                            .then(content => {
                                msg.payload = content;
                                delete msg.error;
                                this.status({});
                                this.send(msg); 
                            })
                            .catch(err => {
                                this.error(RED._("box.error.download-failed",{
                                    err:err.toString()
                                }), msg);
                                this.status({fill:"red",shape:"ring",text:"box.status.failed"});
                            });
                    }, err => {
                        this.error(RED._("box.error.path-resolve-failed", {
                            err:err.toString()
                        }), msg);
                        this.status({fill:"red",shape:"ring",text:"box.status.failed"});
                    });
            });
        }
    }
    RED.nodes.registerType("box", BoxDownloadNode);

    function BoxOutNode(n) {
        RED.nodes.createNode(this,n);
        this.filename = n.filename || "";
        this.localFilename = n.localFilename || "";
        this.box = RED.nodes.getNode(n.box);
        var node = this;
        if (!this.box || !this.box.hasCredentials) {
            this.warn(RED._("box.warn.missing-credentials"));
            return;
        }

        node.on("input", function(msg) {
            var filename = node.filename || msg.filename;
            if (filename === "") {
                node.error(RED._("box.error.no-filename-specified"));
                return;
            }
            var path = filename.split("/");
            var basename = path.pop();
            node.status({fill:"blue",shape:"dot",text:"box.status.resolving-path"});
            var localFilename = node.localFilename || msg.localFilename;
            if (!localFilename && typeof msg.payload === "undefined") {
                return;
            }
            node.box.resolvePath(path, function(err, parent_id) {
                if (err) {
                    node.error(RED._("box.error.path-resolve-failed",{err:err.toString()}),msg);
                    node.status({fill:"red",shape:"ring",text:"box.status.failed"});
                    return;
                }
                node.status({fill:"blue",shape:"dot",text:"box.status.uploading"});
                var r = node.box.request({
                    method: 'POST',
                    url: 'https://upload.box.com/api/2.0/files/content',
                }, function(err, data) {
                    if (err) {
                        if (data && data.status === 409 &&
                            data.context_info && data.context_info.conflicts) {
                            // existing file, attempt to overwrite it
                            node.status({fill:"blue",shape:"dot",text:"box.status.overwriting"});
                            var r = node.box.request({
                                method: 'POST',
                                url: 'https://upload.box.com/api/2.0/files/'+
                                    data.context_info.conflicts.id+'/content',
                            }, function(err, data) {
                                if (err) {
                                    node.error(RED._("box.error.upload-failed",{err:err.toString()}),msg);
                                    node.status({fill:"red",shape:"ring",text:"box.status.failed"});
                                    return;
                                }
                                node.status({});
                            });
                            var form = r.form();
                            if (localFilename) {
                                form.append('filename', fs.createReadStream(localFilename), { filename: basename });
                            } else {
                                form.append('filename', RED.util.ensureBuffer(msg.payload), { filename: basename });
                            }
                        } else {
                            node.error(RED._("box.error.upload-failed",{err:err.toString()}),msg);
                            node.status({fill:"red",shape:"ring",text:"box.status.failed"});
                        }
                        return;
                    }
                    node.status({});
                });
                var form = r.form();
                form.append('filename', localFilename ? fs.createReadStream(localFilename) : RED.util.ensureBuffer(msg.payload), { filename: basename });
                form.append('parent_id', parent_id);
            });
        });
    }
    RED.nodes.registerType("box out",BoxOutNode);
};
