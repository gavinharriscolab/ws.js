
const crypto = require('crypto');
const select = require('./xpath').SelectNodes;
const Dom = require('xmldom').DOMParser;

var pki = require('node-forge').pki;
var ejs = require('ejs'),
    fs = require('fs');

var encSchemes = {
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5': 'RSAES-PKCS1-V1_5',
    'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p': 'RSA-OAEP'
}

const templates = {
  // 'encrypted-key': fs.readFileSync(path.join(__dirname, 'templates', 'encrypted-key.tpl.xml'), 'utf8'),
  'keyinfo': fs.readFileSync('./template/keyinfo.tmpl.xml', 'utf8'),
  'encblock': fs.readFileSync('./template/encrypted-block.tmpl.xml', 'utf8')
};

/**
* @Param doc - the XML Document to encrypt
* @Param xpathToContents - An array of XPath expressions to the contents to be
*                          encrypted.
*/
exports.encrypt = function (options, doc) {

    options.doc = new Dom().parseFromString(doc);

    return createSymetricKey(options)
        .then(createKeyInfoXmlFragment)
        .then(encryptRequiredXmlParts);

};



function createSymetricKey(options) {

    return new Promise( function(resolve, reject) {

        crypto.randomBytes(16, function(err, key) {
            if(err) {
                return reject(err);
            }

            resolve({"key": key, "options": options});
        })

    });

}

function createKeyInfoXmlFragment(data) {
    return new Promise( function(resolve, reject) {

        var rsa_pub = pki.publicKeyFromPem(data.options.rsa_pub);
        var encrypted = rsa_pub.encrypt(data.key.toString('binary'), encSchemes["http://www.w3.org/2001/04/xmlenc#rsa-1_5"]);
        var base64EncodedEncryptedKey = new Buffer(encrypted, 'binary').toString('base64');

        var params = {
            keyHash: data.options.key_hash,
            cipherValue: base64EncodedEncryptedKey
        }

        var result = ejs.render(templates.keyinfo, params);

        data.keyInfo = result;

        resolve(data);

    });
}

/*
    This function encrypts the required parts of the document. The outcome of this
    method is an encrypted document ready to go.
*/
function encryptRequiredXmlParts(data) {

    return new Promise( function(resolve, reject) {

        var proms = [];
        var keyDoc = new Dom().parseFromString(data.keyInfo);
        var referenceNode = select(keyDoc, "//*[local-name(.)='ReferenceList']")[0];

        for(var i = 0; i < data.options.xpathToContents.length; i++) {

            proms.push(
                new Promise( function(res, rej) {
                    var nodes = select(data.options.doc, data.options.xpathToContents[i]);

                    if(nodes.length > 0) {

                        var strToEncrypt = nodes.toString();
                        var parentNode = nodes[0].parentNode;

                        crypto.randomBytes(16, function(err, iv) {
                            var cipher = crypto.createCipheriv("aes-128-cbc", data.key, iv);
                            var encrypted = cipher.update(strToEncrypt, data.options.input_encoding, 'binary') + cipher.final('binary');

                            var params = {
                                blockId: new Date().getTime(),
                                cipherValue: Buffer.concat([iv, new Buffer(encrypted, 'binary')]).toString("base64")
                            }

                            referenceNode.appendChild( new Dom().parseFromString(`<xenc:DataReference xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" URI="#${params.blockId}"/>`) )

                            var result = ejs.render(templates.encblock, params);

                            parentNode.removeChild(nodes);
                            parentNode.appendChild( new Dom().parseFromString(result));

                            res();
                        });

                    } else {
                        res();
                    }
                })
            );

        }

        Promise.all(proms)
            .then( function() {
                select(data.options.doc, "//*[local-name(.)='Security']")[0].appendChild(keyDoc);
                resolve(data);
            })
            .catch(reject);

            // data.options.doc;
        });
}
