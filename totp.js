const crypto = require("crypto");

const base32Decode = (base32) => {
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let output = new Uint8Array((base32.length * 5) / 8 | 0);

    for (let i = 0; i < base32.length; i++) {
        const val = base32Chars.indexOf(base32[i].toUpperCase());
        if (val === -1) throw new Error("Invalid Base32 character");
        bits += val.toString(2).padStart(5, "0");
    }

    for (let i = 0; i < output.length; i++) {
        output[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    return output;
};

const generateTOTP = (secret, timeStep = 30, digits = 6) => {
    const decodedKey = base32Decode(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / timeStep);

    // Convert counter to 8-byte buffer
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeUInt32BE(counter, 4);

    // Compute HMAC-SHA1
    const hmac = crypto.createHmac("sha1", decodedKey);
    hmac.update(counterBuffer);
    const hmacResult = hmac.digest();

    // Dynamic Truncation
    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const binaryCode =
        ((hmacResult[offset] & 0x7f) << 24) |
        ((hmacResult[offset + 1] & 0xff) << 16) |
        ((hmacResult[offset + 2] & 0xff) << 8) |
        (hmacResult[offset + 3] & 0xff);

    // Compute TOTP
    const otp = binaryCode % Math.pow(10, digits);
    return otp.toString().padStart(digits, "0");
};

module.exports = { generateTOTP };
