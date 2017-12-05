
const crypto = require('crypto');
const select = require('../../../xpath').SelectNodes;
const Dom = require('xmldom').DOMParser;

const forge = require('node-forge');
var pki = forge.pki;
var ejs = require('ejs'),
    fs = require('fs');

var encSchemes = {
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5': 'RSAES-PKCS1-V1_5',
    'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p': 'RSA-OAEP',
    'http://www.w3.org/2001/04/xmlenc#aes128-cbc': 'AES-CBC'
}

const templates = {
  // 'encrypted-key': fs.readFileSync(path.join(__dirname, 'templates', 'encrypted-key.tpl.xml'), 'utf8'),
  'keyinfo': fs.readFileSync(__dirname + '/template/keyinfo.tmpl.xml', 'utf8'),
  'encblock': fs.readFileSync( __dirname + '/template/encrypted-block.tmpl.xml', 'utf8')
};

/**
* @Param doc - the XML Document to encrypt
* @Param xpathToContents - An array of XPath expressions to the contents to be
*                          encrypted.
*/
exports.encrypt = function (options, doc) {

    var key = forge.random.getBytesSync(16);
    var cipher = forge.cipher.createCipher('AES-CBC', key);

    var rsa_pub = pki.publicKeyFromPem( options.rsa_pub);
    var encrypted = rsa_pub.encrypt( key.toString('binary'), encSchemes["http://www.w3.org/2001/04/xmlenc#rsa-1_5"]);
    var base64EncodedEncryptedKey = new Buffer(encrypted, 'binary').toString('base64');

    var params = {
        keyHash: options.key_hash,
        cipherValue: base64EncodedEncryptedKey
    }

    keyInfo = ejs.render(templates.keyinfo, params);

    var keyDoc = new Dom().parseFromString(keyInfo);
    var referenceNode = select(keyDoc, "//*[local-name(.)='ReferenceList']")[0];

    for(var i = 0; i < options.xpathToContents.length; i++) {

        var nodes = select(doc, options.xpathToContents[i]);

        if(nodes.length > 0) {
            var strToEncrypt = nodes.toString();
            var parentNode = nodes[0].parentNode;

            var iv = forge.random.getBytesSync(16);

            var cipher = forge.cipher.createCipher('AES-CBC', key);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(strToEncrypt));
            cipher.finish();

            var encrypted = cipher.output;

            console.log(encrypted);

            var params = {
                blockId: new Date().getTime(),
                cipherValue: new Buffer(encrypted.getBytes(), "utf-8").toString("base64")
            }

            referenceNode.appendChild( new Dom().parseFromString(`<xenc:DataReference xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" URI="#${params.blockId}"/>`) )

            var result = ejs.render(templates.encblock, params);

            for(var p = 0; p < nodes.length; p++) {
                parentNode.removeChild(nodes[p]);
            }
            parentNode.appendChild( new Dom().parseFromString(result));


        }


    }

    select(doc, "//*[local-name(.)='Security']")[0].appendChild(keyDoc);

    return doc;
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

            forge.


            proms.push(
                new Promise( function(res, rej) {
                    var nodes = select(data.options.doc, data.options.xpathToContents[i]);

                    if(nodes.length > 0) {

                        var strToEncrypt = nodes.toString();
                        var parentNode = nodes[0].parentNode;

                        crypto.randomBytes(16, function(err, iv) {

                            console.log(data.key);

                            var cipher = forge.cipher.createCipher('AES-CBC', data.key);
                            cipher.start({iv: iv});
                            cipher.update( new Buffer(strToEncrypt, 'utf-8') );
                            cipher.finish();

                            var encrypted = cipher.output;
                            // cipher.update(strToEncrypt, data.options.input_encoding, 'binary') + cipher.final('binary');

                            var params = {
                                blockId: new Date().getTime(),
                                cipherValue: Buffer.concat([iv, new Buffer(encrypted, 'binary')]).toString("base64")
                            }

                            referenceNode.appendChild( new Dom().parseFromString(`<xenc:DataReference xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" URI="#${params.blockId}"/>`) )

                            var result = ejs.render(templates.encblock, params);

                            for(var p = 0; p < nodes.length; p++) {
                                parentNode.removeChild(nodes[p]);
                            }
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
