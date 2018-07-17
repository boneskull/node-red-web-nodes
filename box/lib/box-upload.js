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

const fs = require('fs');

module.exports = RED => {

    function BoxOutNode(n) {
        RED.nodes.createNode(this, n);
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
            node.status({
                fill: "blue",
                shape: "dot",
                text: "box.status.resolving-path"
            });
            var localFilename = node.localFilename || msg.localFilename;
            if (!localFilename && typeof msg.payload === "undefined") {
                return;
            }
            node.box.resolvePath(path, function(err, parent_id) {
                if (err) {
                    node.error(RED._("box.error.path-resolve-failed", {
                        err: err.toString()
                    }), msg);
                    node.status({
                        fill: "red",
                        shape: "ring",
                        text: "box.status.failed"
                    });
                    return;
                }
                node.status({
                    fill: "blue",
                    shape: "dot",
                    text: "box.status.uploading"
                });
                var r = node.box.request({
                    method: 'POST',
                    url: 'https://upload.box.com/api/2.0/files/content',
                }, function(err, data) {
                    if (err) {
                        if (data && data.status === 409 &&
                            data.context_info && data.context_info.conflicts) {
                            // existing file, attempt to overwrite it
                            node.status({
                                fill: "blue",
                                shape: "dot",
                                text: "box.status.overwriting"
                            });
                            var r = node.box.request({
                                method: 'POST',
                                url: 'https://upload.box.com/api/2.0/files/' +
                                    data.context_info.conflicts.id + '/content',
                            }, function(err, data) {
                                if (err) {
                                    node.error(RED._("box.error.upload-failed", {
                                        err: err.toString()
                                    }), msg);
                                    node.status({
                                        fill: "red",
                                        shape: "ring",
                                        text: "box.status.failed"
                                    });
                                    return;
                                }
                                node.status({});
                            });
                            var form = r.form();
                            if (localFilename) {
                                form.append('filename', fs.createReadStream(localFilename), {
                                    filename: basename
                                });
                            } else {
                                form.append('filename', RED.util.ensureBuffer(msg.payload), {
                                    filename: basename
                                });
                            }
                        } else {
                            node.error(RED._("box.error.upload-failed", {
                                err: err.toString()
                            }), msg);
                            node.status({
                                fill: "red",
                                shape: "ring",
                                text: "box.status.failed"
                            });
                        }
                        return;
                    }
                    node.status({});
                });
                var form = r.form();
                form.append('filename', localFilename ? fs.createReadStream(localFilename) : RED.util
                    .ensureBuffer(msg.payload), {
                        filename: basename
                    });
                form.append('parent_id', parent_id);
            });
        });
    }
    RED.nodes.registerType("box out", BoxOutNode);
};
