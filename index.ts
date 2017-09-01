import * as CryptoJS from "crypto-js";

var Curve25519 = require("./lib/Curve25519.js")
var BigInt = require("./lib/BigInt.js");

interface WordArray {
    toString(encoding: any): string;
    sigBytes: number;
    words: number[];
}

function intCompare(x, y) {
    var z = ~(x ^ y)
    z &= z >> 16
    z &= z >> 8
    z &= z >> 4
    z &= z >> 2
    z &= z >> 1
    return z & 1
}

// constant-time string comparison
var HLPcompare = function (str1, str2) {
    if (str1.length !== str2.length)
        return false
    var i = 0, result = 0
    for (; i < str1.length; i++)
        result |= str1[i].charCodeAt(0) ^ str2[i].charCodeAt(0)
    return intCompare(result, 0)
}

export class MultiParty {
    usedIVs: string[] = [];
    privateKey: any;
    publicKey: any;
    nickname: string;

    buddies: any = {};

    HMAC(msg, key) {
        return CryptoJS.HmacSHA512(
            msg, key
        ).toString(CryptoJS.enc.Base64)
    }

    correctIvLength(iv: string) {
        var ivAsWordArray = CryptoJS.enc.Base64.parse(iv)
        var ivAsArray = ivAsWordArray.words
        ivAsArray.push(0)  // adds 0 as the 4th element, causing the equivalent
        // bytestring to have a length of 16 bytes, with
        // \x00\x00\x00\x00 at the end.
        // without this, crypto-js will take in a counter of
        // 12 bytes, and the first 2 counter iterations will
        // use 0, instead of 0 and then 1.
        // see https://github.com/cryptocat/cryptocat/issues/258
        return CryptoJS.lib.WordArray.create(ivAsArray)
    }

    reset() {
        this.usedIVs = [];
    }

    decryptAES(msg, c, iv) {
        var opts = {
            mode: CryptoJS.mode.CTR,
            iv: this.correctIvLength(iv),
            padding: CryptoJS.pad.NoPadding
        }
        var aesctr = CryptoJS.AES.decrypt(
            msg,
            c,
            opts
        )
        return aesctr
    }

    encryptAES(msg, c, iv) {
        var opts = {
            mode: CryptoJS.mode.CTR,
            iv: this.correctIvLength(iv),
            padding: CryptoJS.pad.NoPadding
        }
        var aesctr = CryptoJS.AES.encrypt(
            msg,
            c,
            opts
        )
        return aesctr.toString()
    }

    genPrivateKey() {
        return BigInt.randBigInt(256);
    }

    genPublicKey(privateKey) {
        return Curve25519.ecDH(privateKey)
    }

    genSharedSecret(nickname) {
        //I need to convert the BigInt to WordArray here. I do it using the Base64 representation.
        var sharedSecret = CryptoJS.SHA512(
            CryptoJS.enc.Base64.parse(
                BigInt.bigInt2base64(
                    Curve25519.ecDH(
                        this.privateKey,
                        this.buddies[nickname].mpPublicKey
                    ),
                    32
                )
            )
        )
        return {
            'message': CryptoJS.lib.WordArray.create(sharedSecret.words.slice(0, 8)),
            'hmac': CryptoJS.lib.WordArray.create(sharedSecret.words.slice(8, 16))
        }
    }

    genFingerprint(nickname) {
        var key = this.publicKey;
        if (nickname) {
            key = this.buddies[nickname].mpPublicKey
        }
        return CryptoJS.SHA512(
            CryptoJS.enc.Base64.parse(
                BigInt.bigInt2base64(key, 32)
            )
        ).toString().substring(0, 40).toUpperCase()
    }

    sendPublicKey(nickname) {
        var answer = {}
        answer['type'] = 'publicKey'
        answer['text'] = {}
        answer['text'][nickname] = {}
        answer['text'][nickname]['message'] = BigInt.bigInt2base64(
            this.publicKey, 32
        )
        return JSON.stringify(answer)
    }

    messageTag(message) {
        for (var i = 0; i !== 8; i++) {
            message = CryptoJS.SHA512(message)
        }
        return message.toString(CryptoJS.enc.Base64)
    }

    randomBytes(len: number): WordArray {
        var u8Array = new Uint8Array(len);
        window.crypto.getRandomValues(u8Array);

        var words = [], i = 0, len = u8Array.length;

        while (i < len) {
            words.push(
                (u8Array[i++] << 24) |
                (u8Array[i++] << 16) |
                (u8Array[i++] << 8) |
                (u8Array[i++])
            );
        }
        var sig = CryptoJS.lib.WordArray.create();
        sig.sigBytes = words.length * 4;
        sig.words = words;
        return sig;
    }

    sendMessage(messageString: string) {
        //Convert from UTF8
        var message = CryptoJS.enc.Utf8.parse(messageString)
        // Add 64 bytes of padding
        message.concat(this.randomBytes(64))
        var encrypted = {
            text: {},
            type: 'message'
        }
        //Sort recipients
        var sortedRecipients = []
        for (var b in this.buddies) {
            if (this.buddies[b].mpSecretKey) {
                sortedRecipients.push(b)
            }
        }
        sortedRecipients.sort()
        var hmac = CryptoJS.lib.WordArray.create()
        //For each recipient
        var i, iv
        for (i = 0; i !== sortedRecipients.length; i++) {
            //Generate a random IV
            iv = this.randomBytes(12).toString(CryptoJS.enc.Base64);
            // Do not reuse IVs
            while (this.usedIVs.indexOf(iv) >= 0) {
                iv = this.randomBytes(12).toString(CryptoJS.enc.Base64);
            }
            this.usedIVs.push(iv)
            //Encrypt the message
            encrypted['text'][sortedRecipients[i]] = {}
            encrypted['text'][sortedRecipients[i]]['message'] = this.encryptAES(
                message,
                this.buddies[sortedRecipients[i]].mpSecretKey['message'],
                iv
            )
            encrypted['text'][sortedRecipients[i]]['iv'] = iv
            //Append to HMAC
            hmac.concat(CryptoJS.enc.Base64.parse(encrypted['text'][sortedRecipients[i]]['message']))
            hmac.concat(CryptoJS.enc.Base64.parse(encrypted['text'][sortedRecipients[i]]['iv']))
        }
        encrypted['tag'] = message.clone()
        //For each recipient again
        for (i = 0; i !== sortedRecipients.length; i++) {
            //Compute the HMAC
            encrypted['text'][sortedRecipients[i]]['hmac'] = this.HMAC(
                hmac,
                this.buddies[sortedRecipients[i]].mpSecretKey['hmac']
            )
            //Append to tag
            encrypted['tag'].concat(CryptoJS.enc.Base64.parse(encrypted['text'][sortedRecipients[i]]['hmac']))
        }
        //Compute tag
        encrypted['tag'] = this.messageTag(encrypted['tag'])
        return JSON.stringify(encrypted)
    }

    destroyBuddy(nick: string) {
        delete this.buddies[nick];
    }

    addBuddy(nick: string) {
        this.buddies[nick] = { };
    }

    // Receive message. Detects requests/reception of public keys.
    receiveMessage(sender, message, sendPK?: (string) => void) {
        var myName = this.nickname;
        var buddy = this.buddies[sender]
        try {
            message = JSON.parse(message)
        }
        catch (err) {
            console.log('multiParty: failed to parse message object', err.message)
            console.log(message);
            return false
        }
        if (typeof (message['text'][myName]) === 'object') {
            // Detect public key reception, store public key and generate shared secret
            if (message.type === 'publicKey') {
                var msg = message.text[myName].message
                if (typeof (msg) !== 'string') {
                    console.log('multiParty: publicKey without message field')
                    return false
                }
                var publicKey = BigInt.base642bigInt(msg)
                // if we already have a public key for this buddy, make sure it's
                // the one we have
                if (!buddy.mpPublicKey) {
                    buddy.mpPublicKey = publicKey;
                    buddy.mpSecretKey = this.genSharedSecret(sender);
                }
                return false
            }
            // Detect public key request and send public key
            else if (message['type'] === 'publicKeyRequest') {
                if (sendPK) {
                    sendPK(sender);
                }
            }
            else if (message['type'] === 'message') {
                // Make sure message is being sent to all chat room participants
                var recipients = Object.keys(this.buddies)
                recipients.push(this.nickname);
                var missingRecipients = []
                recipients.splice(recipients.indexOf(sender), 1)
                for (var r = 0; r !== recipients.length; r++) {
                    try {
                        if (typeof (message['text'][recipients[r]]) === 'object') {
                            var noMessage = typeof (message['text'][recipients[r]]['message']) !== 'string'
                            var noIV = typeof (message['text'][recipients[r]]['iv']) !== 'string'
                            var noHMAC = typeof (message['text'][recipients[r]]['hmac']) !== 'string'
                            if (noMessage || noIV || noHMAC) {
                                missingRecipients.push(recipients[r])
                            }
                        }
                        else {
                            missingRecipients.push(recipients[r])
                        }
                    }
                    catch (err) {
                        missingRecipients.push(recipients[r])
                    }
                }
                // Decrypt message
                if (!this.buddies[sender].mpSecretKey) {
                    return false
                }
                // Sort recipients
                var sortedRecipients = Object.keys(message['text']).sort()
                // Check HMAC
                var hmac = CryptoJS.lib.WordArray.create()
                var i
                for (i = 0; i !== sortedRecipients.length; i++) {
                    if (missingRecipients.indexOf(sortedRecipients[i]) < 0) {
                        hmac.concat(CryptoJS.enc.Base64.parse(message['text'][sortedRecipients[i]]['message']))
                        hmac.concat(CryptoJS.enc.Base64.parse(message['text'][sortedRecipients[i]]['iv']))
                    }
                }
                if (
                    !HLPcompare(
                        message['text'][myName]['hmac'],
                        this.HMAC(hmac, this.buddies[sender].mpSecretKey['hmac'])
                    )
                ) {
                    console.log('multiParty: HMAC failure')
                    return false
                }
                // Check IV reuse
                if (this.usedIVs.indexOf(message['text'][myName]['iv']) >= 0) {
                    console.log('multiParty: IV reuse detected, possible replay attack')
                    return false
                }
                this.usedIVs.push(message['text'][myName]['iv'])
                // Decrypt
                var plaintext = this.decryptAES(
                    message['text'][myName]['message'],
                    this.buddies[sender].mpSecretKey['message'],
                    message['text'][myName]['iv']
                )
                // Check tag
                var messageTag = plaintext.clone()
                for (i = 0; i !== sortedRecipients.length; i++) {
                    messageTag.concat(CryptoJS.enc.Base64.parse(message['text'][sortedRecipients[i]]['hmac']))
                }
                if (this.messageTag(messageTag) !== message['tag']) {
                    console.log('multiParty: message tag failure')
                    return false
                }
                // Remove padding
                if (plaintext.sigBytes < 64) {
                    console.log('multiParty: invalid plaintext size')
                    return false
                }
                plaintext = CryptoJS.lib.WordArray.create(plaintext.words, plaintext.sigBytes - 64)
                // Convert to UTF8
                return plaintext.toString(CryptoJS.enc.Utf8)
            }
            else {
                console.log('multiParty: Unknown message type: ' + message['type'])
            }
        }
        return false
    }

    constructor(nickname: string, profile?: string) {
        this.nickname = nickname;

        if(profile) {
            this.privateKey = BigInt.base642bigInt(profile);
        } else {
            this.privateKey = BigInt.randBigInt(256);
        }

        this.publicKey = Curve25519.ecDH(this.privateKey);
    }
}
