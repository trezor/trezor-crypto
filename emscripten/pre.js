// stub importScripts for the faulty detection of web worker env
if (typeof importScripts === 'undefined'
    && typeof WorkerGlobalScope !== 'undefined'
    && this instanceof WorkerGlobalScope
) {
    this.importScripts = function () {
        throw new Error('importScripts is a stub');
    };
}

function prepareModule(binary) {
    var Module = {};
    Module['wasmBinary'] = new Uint8Array(binary);
