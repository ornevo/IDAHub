export default function createHashCalculatigWorker(onmessage, onerror) {
    // Since the worker's source must be a url with the js, we create such url with the worker code here.
    let hashCalculationWorker = new Worker( URL.createObjectURL(
        new Blob([
            "importScripts('https://cdnjs.cloudflare.com/ajax/libs/js-sha256/0.9.0/sha256.min.js'); \n" +
            "onmessage = function(e) { // eslint-disable-line no-unused-vars                        \n" +
            "    var content = e.data;                                                              \n" +
            "                                                                                       \n" +
            "    try {                                                                              \n" +
            "        var hash = self.sha256(content);                                               \n" +
            "    } catch(e) {                                                                       \n" +
            "        throw new Error('JS-SHA256 script was not loaded. Can\\'t calculate hash.');   \n" +
            "    }                                                                                  \n" +
            "    postMessage(hash);                                                                 \n" +
            "};"
        ])
    ));

    hashCalculationWorker.onmessage = onmessage;
    hashCalculationWorker.onerror = onerror;
    return hashCalculationWorker;
}