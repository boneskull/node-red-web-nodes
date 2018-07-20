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

module.exports = RED => {

    const SCOPE_ENTERPRISE = 'ENTERPRISE';
    const SCOPE_GLOBAL = 'GLOBAL';

    class BoxAddMetadataNode {
        /**
         * Creates an instance of BoxAddMetadataNode.
         * @param {*} n
         * @memberof BoxAddMetadataNode
         */
        constructor(n) {
            RED.nodes.createNode(this, n);

            /**
             * @type {string|number}
             */
            this.fileId = n.fileId;

            /**
             * @type {string}
             */
            this.templateKey = n.templateKey;

            /**
             * @type {Object}
             */
            this.metadata = n.metadata;

            /**
             * @type {string}
             */
            this.scope = n.scope || SCOPE_ENTERPRISE;

            /**
             * @type {BoxAPINode}
             */
            this.box = RED.nodes.getNode(n.box);

            if (!this.box || !this.box.hasCredentials) {
                this.warn(RED._("box.warn.missing-credentials"));
                return;
            }

            this.on("input", msg => {
                const fileId = this.fileId || msg.fileId;
                const templateKey = this.templateKey || msg.templateKey;
                const metadata = this.metadata || msg.metadata || msg.payload || {};
                const scope = this.scope || msg.scope;

                if (!fileId) {
                    this.error(RED._("box.error.no-filename-specified"));
                    return;
                }
                if (!templateKey) {
                    this.error(RED._('box.error.no-template-key-specified'));
                    return;
                }
                if (scope !== SCOPE_ENTERPRISE && scope !== SCOPE_GLOBAL) {
                    this.error(RED._('box.error.invalid-scope'));
                    return;
                }

                msg.templateKey = templateKey;
                msg.fileId = fileId;
                msg.scope = scope;
                msg.payload = metadata;

                this.status({
                    fill: "blue",
                    shape: "dot",
                    text: "box.status.adding-metadata"
                });

                this.box.client.files.addMetadata(
                        fileId,
                        this.box.client.metadata.scopes[scope],
                        templateKey,
                        metadata
                    )
                    .catch(err => Promise.reject(RED._('box.error.add-metadata-failed', {
                        err: err.toString()
                    })))
                    .then(newMetadata => {
                        msg.payload = newMetadata;
                        delete msg.error;
                        this.status({});
                        this.send(msg);
                    })
                    .catch(err => {
                        this.error(err, msg);
                        this.status({
                            fill: "red",
                            shape: "ring",
                            text: "box.status.failed"
                        });
                    });
            });
        }
    }
    RED.nodes.registerType("box-metadata", BoxAddMetadataNode);
}
