class CryptoUtils {
    constructor() {}

    static intToUint(val) {
        val = parseInt(val);
        return val < 0 ? val + 4294967296 : val;
    }

    static uintToInt(val) {   
        return val > 2147483647 ? val - 4294967296 : val;
    }

    static isArray(a) {
        return Array.isArray(a);
    }

    static cloneArray(a) {
        return Array.from(a);
    }

    static isObject(o) {
        return o === Object(o);
    }

    static log4x4matrix(s) {
        console.log(`${s[0][0].toString(16)}\t${s[1][0].toString(16)}\t${s[2][0].toString(16)}\t${s[3][0].toString(16)}\n`);
        console.log(`${s[0][1].toString(16)}\t${s[1][1].toString(16)}\t${s[2][1].toString(16)}\t${s[3][1].toString(16)}\n`);
        console.log(`${s[0][2].toString(16)}\t${s[1][2].toString(16)}\t${s[2][2].toString(16)}\t${s[3][2].toString(16)}\n`);
        console.log(`${s[0][3].toString(16)}\t${s[1][3].toString(16)}\t${s[2][3].toString(16)}\t${s[3][3].toString(16)}\n`);
    }

    static reverseString(v){
        return v.split("").reverse().join("");
    }

    static hexStringToBuffer(hexString, padStart = false) {
        if(padStart && hexString.length % 2){
            hexString = "0" + hexString;
        }

        let lengthBytes = Math.ceil(hexString.length / 2);
        var bytes = new ArrayBuffer(lengthBytes);
        let b = new Uint8Array(bytes);        
        let i = 0;
        let j = 0;
        while(i < hexString.length)
        {
            let tpl = hexString.substr(i,2);
            tpl = tpl.length == 1 ? tpl + "0" : tpl;
            b[j] = CryptoUtils.intToUint(parseInt(tpl, 16)); 
            i += 2;
            ++j;         
        }

        return bytes;
    }

    static hexStringToArray(hexString, padStart = false) {
        return CryptoUtils.cloneArray(new Uint8Array(CryptoUtils.hexStringToBuffer(hexString,padStart)));
    }

    static bufferToHexString(bytes, padStart = false) {
        let b = new Uint8Array(bytes);
        var hexString = [];

        for(let i = 0; i < b.length; ++i)
        {
            let t = b[i].toString(16);
            t = t.length == 1 ? ("0" + t) : t;
            hexString.push(t);
        }  

        hexString = hexString.join("");
        while(padStart && hexString[0] == "0") {
            hexString = hexString.substr(1,hexString.length-1);
        }

        return hexString;
    }

    static xorArrays(a,b) {
        if(a.length != b.length) {
            throw new Error(`xorArrays: incorrect sizes of input arrays ${a.length} != ${b.length}`);
        }

        var res = [];

        for(let i = 0; i < a.length; ++i){
            res.push(a[i] ^ b[i]);
        }

        return res;
    }

    static xorArraysTo(a,b,out) {
        if(a.length != b.length || out.length != a.length) {
            throw new Error(`xorArrays: incorrect sizes of input arrays ${a.length} != ${b.length}`);
        }

        for(let i = 0; i < a.length; ++i){
            out[i] = a[i] ^ b[i];
        }
    }

    static textToUint8Array(message) {
        return new TextEncoder().encode(message);  
    }

    static addPadding(bytes, blockSize = 16, zeroes = false, dir = "e") {
        let len = bytes.length;
        let needPadding = blockSize - (len % blockSize);

        bytes = CryptoUtils.cloneArray(bytes);

        if (needPadding > 0 && needPadding < blockSize) {
            var padding;

            if (zeroes) {
                padding = new Array(needPadding);

                for (var i = 0; i < needPadding; i++) {
                    padding[i] = 0;
                }
            } else {
                padding = new Uint8Array(needPadding);
                window.crypto.getRandomValues(padding);
                padding = CryptoUtils.cloneArray(padding);
            }

            if(dir == "s") {
                return padding.concat(bytes);
            }

            if(dir == "e") {
                return bytes.concat(padding);
            }
        }

        return bytes;
    }

    static str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
            for (let i = 0, strLen = str.length; i < strLen; i++) {
                bufView[i] = str.charCodeAt(i);
            }
        return buf;
    }

    static hexStringFromPem(pem,pemHeader,pemFooter) {
        // fetch the part of the PEM string between header and footer
        const v1h = "-----BEGIN PUBLIC KEY-----";

        pemHeader = pemHeader || v1h;
        pemFooter = pemFooter || "-----END PUBLIC KEY-----";

        let offset = 18;

        if(pemHeader == v1h) {
            offset = 66;
        }

        const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
        // base64 decode the string to get the binary data
        const binaryDerString = window.atob(pemContents);
        // convert from a binary string to an ArrayBuffer
        const binaryDer = CryptoUtils.str2ab(binaryDerString);
        const res = CryptoUtils.bufferToHexString(binaryDer);
        return res.substring(offset,res.length - 10);
    }

    static tsNow(){
        let date = new Date();
        return ((date.getTime() * 10000) + 621355968000000000) - (date.getTimezoneOffset() * 600000000);
    }

    static nextRandomInt(maxValue) {
        return Math.floor(Math.random() * maxValue)
    }

    static nextRandomArray(v) {
        window.crypto.getRandomValues(v);
    }
}

class AES {
    constructor(key){
        this.key = CryptoUtils.cloneArray(key);
        this.w = [];

        // Number of rounds by keysize
        this.NUMBER_OF_ROUNDS = {16: 10, 24: 12, 32: 14};

        // Round constant words
        this.R_CON = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000, 0x9a000000, 0x2f000000, 0x5e000000, 0xbc000000, 0x63000000, 0xc6000000, 0x97000000, 0x35000000, 0x6a000000, 0xd4000000, 0xb3000000, 0x7d000000, 0xfa000000, 0xef000000, 0xc5000000, 0x91000000];

        // S-box and Inverse S-box (S is for Substitution)
        this.S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
        this.S_I = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

        this.Nr = this.NUMBER_OF_ROUNDS[this.key.length];
        this.Nb = 4;
        this.Nk = this.key.length / 4;

        this.KeyExpansion();

        this.debug = false;
    }

    static get blockSizeByte() {
        return 16;
    }

    set allowDebugOutput(v) {
        this.debug = v;
    }

    getw(i,j) {
        return this.w[i*this.Nb + j];
    }

    getwi(i) {
        return this.w[i];
    }

    getS(val) {
        let v = ((val >> 4) & 0xf) * 16 + (val & 0xf);
        this.debug && console.log(`getS arg=${val.toString(16)} index=${v}`);
        return this.S[v];
    }

    getSinv(val) {
        let v = ((val >> 4) & 0xf) * 16 + (val & 0xf);
        this.debug && console.log(`getS arg=${val.toString(16)} index=${v}`);
        return this.S_I[v];
    }

    static toStateMatrix(bytes) {
        var result = [];
        for (let i = 0; i < 4; ++i) {
            result.push([bytes[0 + 4*i],
                bytes[1 + 4*i],
                bytes[2 + 4*i],
                bytes[3 + 4*i]]);
        }
        return result;
    }

    static fromStateMatrix(s) {
        var bytes = new ArrayBuffer(16);
        let b = new Uint8Array(bytes);
        for (let i = 0; i < 4; ++i) {
            b[0 + 4*i] = s[i][0];
            b[1 + 4*i] = s[i][1];
            b[2 + 4*i] = s[i][2];
            b[3 + 4*i] = s[i][3];
        }
        return bytes;
    }

    encrypt(inp) {
        var state = AES.toStateMatrix(inp);
        this.debug && CryptoUtils.log4x4matrix(state);
        this.AddRoundKey(state,0);
        this.debug && CryptoUtils.log4x4matrix(state);

        let d = this.Nr;
        for(let round = 1; round < d; ++round) {
            this.debug && console.log("round=",round);
            this.SubBytes(state);
            this.debug && CryptoUtils.log4x4matrix(state);
            AES.ShiftRows(state);
            this.debug && CryptoUtils.log4x4matrix(state);
            AES.MixColumns(state);
            this.debug && CryptoUtils.log4x4matrix(state);
            this.AddRoundKey(state,round);
            this.debug && CryptoUtils.log4x4matrix(state);
        }

        this.SubBytes(state);
        this.debug && CryptoUtils.log4x4matrix(state);
        AES.ShiftRows(state);
        this.debug && CryptoUtils.log4x4matrix(state);
        this.AddRoundKey(state,this.Nr);
        this.debug && CryptoUtils.log4x4matrix(state);

        return AES.fromStateMatrix(state);
    }

    decrypt(inp) {
        var state = AES.toStateMatrix(inp);
        this.debug && CryptoUtils.log4x4matrix(state);
        this.AddRoundKey(state,this.Nr);
        this.debug && CryptoUtils.log4x4matrix(state);

        for(let round = this.Nr - 1; round > 0; --round) {
            this.debug && console.log("round=",round);
            AES.InvShiftRows(state);
            this.debug && CryptoUtils.log4x4matrix(state);
            this.InvSubBytes(state);
            this.debug && CryptoUtils.log4x4matrix(state);
            this.AddRoundKey(state,round);
            this.debug && CryptoUtils.log4x4matrix(state);
            AES.InvMixColumns(state);
            this.debug && CryptoUtils.log4x4matrix(state);
        }

        AES.InvShiftRows(state);
        this.debug && CryptoUtils.log4x4matrix(state);
        this.InvSubBytes(state);
        this.debug && CryptoUtils.log4x4matrix(state);
        this.AddRoundKey(state,0);
        this.debug && CryptoUtils.log4x4matrix(state);

        return AES.fromStateMatrix(state);       
    }

    SubBytes(state) {
        state.forEach((e,i,a)=>{
            a[i] = [this.getS(e[0]),this.getS(e[1]),
                    this.getS(e[2]),this.getS(e[3])];
        });
    }

    InvSubBytes(state) {
        state.forEach((e,i,a)=>{
            a[i] = [this.getSinv(e[0]),this.getSinv(e[1]),
                    this.getSinv(e[2]),this.getSinv(e[3])];
        });
    }

    //v * {02}
    static xtime(v) {
        let t = (v << 1);
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    //v * {03}
    static x03(v) {
        let t = AES.xtime(v) ^ v;
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    //v * {09} = v * {01 + 08}
    static x09(v) {
        let t = AES.xtime(AES.xtime(AES.xtime(v))) ^ v;
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    //v * {0b} = v * {08 + 02 + 01}
    static x0b(v) {
        let k = AES.xtime(v);
        let t = AES.xtime(AES.xtime(k)) ^ k ^ v;
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    //v * {0d} = v * {08 + 04 + 01}
    static x0d(v) {
        let k = AES.xtime(v);
        let e = AES.xtime(k);
        let t = AES.xtime(e) ^ e ^ v;
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    //v * {0e} = v * {08 + 04 + 02}
    static x0e(v) {
        let k = AES.xtime(v);
        let e = AES.xtime(k);
        let t = AES.xtime(e) ^ e ^ k;
        if((t & 0x0100) == 0) {
            return t;
        }
        return t ^ 0x11b;
    }

    static toRow(i,v,state) {
        state[0][i] = (v >> 24) & 0xff;
        state[1][i] = (v >> 16) & 0xff;
        state[2][i] = (v >> 8) & 0xff;
        state[3][i] = v & 0xff;
    }

    static toWord(rowi,state) {
        return  CryptoUtils.intToUint((state[0][rowi] << 24) | 
                (state[1][rowi] << 16) |
                (state[2][rowi] << 8) | 
                (state[3][rowi]));
    }

    static ShiftRows(state) {
        let v = this.toWord(1,state);
        AES.toRow(1,CryptoUtils.intToUint((v & 0xff000000) >> 24 & 0xff) | (v << 8),state);

        v = this.toWord(2,state);
        AES.toRow(2,CryptoUtils.intToUint((v & 0xffff0000) >> 16 & 0xffff) | (v << 16),state);

        v = this.toWord(3,state);
        AES.toRow(3,CryptoUtils.intToUint((v & 0xffffff00) >> 8 & 0xffffff) | (v << 24),state);
    }

    static InvShiftRows(state) {
        let v = this.toWord(1,state);
        AES.toRow(1,CryptoUtils.intToUint((v << 24) | (v >> 8 & 0xffffff)),state);

        v = this.toWord(2,state);
        AES.toRow(2,CryptoUtils.intToUint((v << 16) | (v >> 16 & 0xffff)),state);

        v = this.toWord(3,state);
        AES.toRow(3,CryptoUtils.intToUint((v << 8) | (v >> 24 & 0xff)),state);
    }

    static MixColumns(state) {
        for(let i = 0; i < 4; ++i){
            let a = AES.xtime(state[i][0]) ^ AES.x03(state[i][1]) ^ state[i][2] ^ state[i][3];
            let b = AES.xtime(state[i][1]) ^ AES.x03(state[i][2]) ^ state[i][0] ^ state[i][3];
            let c = state[i][0] ^ AES.xtime(state[i][2]) ^ AES.x03(state[i][3]) ^ state[i][1];
            let d = AES.x03(state[i][0]) ^ state[i][1] ^ state[i][2] ^ AES.xtime(state[i][3]);

            state[i] = [a,b,c,d];            
        }
    }

    static InvMixColumns(state) {
        for(let i = 0; i < 4; ++i){
            let a = AES.x0e(state[i][0]) ^ AES.x0b(state[i][1]) ^ AES.x0d(state[i][2]) ^ AES.x09(state[i][3]);
            let b = AES.x09(state[i][0]) ^ AES.x0e(state[i][1]) ^ AES.x0b(state[i][2]) ^ AES.x0d(state[i][3]);
            let c = AES.x0d(state[i][0]) ^ AES.x09(state[i][1]) ^ AES.x0e(state[i][2]) ^ AES.x0b(state[i][3]);
            let d = AES.x0b(state[i][0]) ^ AES.x0d(state[i][1]) ^ AES.x09(state[i][2]) ^ AES.x0e(state[i][3]);

            state[i] = [a,b,c,d];            
        }
    }

    AddRoundKey(state,round) {
        state.forEach((e,i,a)=>{
            let w = this.getw(round,i);
            let v = CryptoUtils.intToUint((e[0] << 24) | (e[1] << 16) | (e[2] << 8) | (e[3]));     
            w = CryptoUtils.intToUint(w ^ v);
            let b = w & 0xff;
            let c = ((w & 0xff00) >> 8) & 0xff;
            let d = ((w & 0xff0000) >> 16) & 0xff;
            let k = ((w & 0xff000000) >> 24) & 0xff;           
            a[i] = [k,d,c,b];
        });        
    }

    KeyExpansion() {
        let i = 0;
        let temp;

        this.w = [];

        while(i < this.Nk) {
            this.w.push(CryptoUtils.intToUint(
                (this.key[4*i] << 24) | 
                (this.key[4*i+1] << 16) |
                (this.key[4*i+2] << 8) | 
                 this.key[4*i+3]));
            ++i;
        }

        i = this.Nk;

        while( i < this.Nb*(this.Nr+1)) {
            temp = this.getwi(i-1);
            this.debug && console.log('w[i-1]=',temp.toString(16));

            if(i % this.Nk == 0) {
                temp = CryptoUtils.intToUint(this.SubWord(AES.RotWord(temp)) ^ this.R_CON[i/this.Nk]);
            } else if (this.Nk > 6 && i % this.Nk == 4){
                temp = this.SubWord(temp);
            }
            this.debug && console.log('temp=',temp.toString(16));

            this.w[i] = CryptoUtils.intToUint(this.getwi(i-this.Nk) ^ temp);
            this.debug && console.log('w[i]=',this.w[i].toString(16));
            ++i;
        }
    }

    static RotWord(t){
        let v = CryptoUtils.intToUint(((t & 0xff000000) >> 24 & 0xff) | (t << 8));
        this.debug && console.log("RotWord", v.toString(16));
        return v;
    }

    SubWord(w) {
        let v = CryptoUtils.intToUint(
            (this.getS((w & 0xff000000) >> 24 & 0xff) << 24) | 
            (this.getS((w & 0xff0000) >> 16 & 0xff) << 16) |
            (this.getS((w & 0xff00) >> 8 & 0xff) << 8) |
             this.getS(w & 0xff)); 
        this.debug && console.log("SubWord", v.toString(16));
        return v;    
    }
}

class AESUnitTest {
    constructor() {

    }

    static key128Expansion(debug) {
        let key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let cr  = new AES(key)
        cr.allowDebugOutput = debug;

        console.dir(`key128Expansion() for object`);
        console.dir(cr);

        let w = [0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c,0xa0fafe17,0x88542cb1,0x23a33939,0x2a6c7605,0xf2c295f2,0x7a96b943,0x5935807a,0x7359f67f,0x3d80477d,0x4716fe3e,0x1e237e44,0x6d7a883b,0xef44a541,0xa8525b7f,0xb671253b,0xdb0bad00,0xd4d1c6f8,0x7c839d87,0xcaf2b8bc,0x11f915bc,0x6d88a37a,0x110b3efd,0xdbf98641,0xca0093fd,0x4e54f70e,0x5f5fc9f3,0x84a64fb2,0x4ea6dc4f,0xead27321,0xb58dbad2,0x312bf560,0x7f8d292f,0xac7766f3,0x19fadc21,0x28d12941,0x575c006e,0xd014f9a8,0xc9ee2589,0xe13f0cc8,0xb6630ca6];

        var r = true;
        for(let i = 0;i<44; ++i)
        {
            if(cr.getwi(i) != w[i]){
                console.error(`Assert [${i}]: ${cr.getwi(i).toString(16)} != ${w[i].toString(16)}`);
                r = false;
            }
        }

        if(!r){
            console.error(`key128Expansion() -- failed!`);
            return;
        }   

        console.log(`key128Expansion() -- ok!`);
    }

    static key192Expansion(debug) {
        let key = [0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b];
        let cr  = new AES(key)
        cr.allowDebugOutput = debug;

        console.dir(`key192Expansion() for object`);
        console.dir(cr);

        let w = [0x8e73b0f7,0xda0e6452,0xc810f32b,0x809079e5,0x62f8ead2,0x522c6b7b,0xfe0c91f7,0x2402f5a5,0xec12068e,0x6c827f6b,0x0e7a95b9,0x5c56fec2,0x4db7b4bd,0x69b54118,0x85a74796,0xe92538fd,0xe75fad44,0xbb095386,0x485af057,0x21efb14f,0xa448f6d9,0x4d6dce24,0xaa326360,0x113b30e6,0xa25e7ed5,0x83b1cf9a,0x27f93943,0x6a94f767,0xc0a69407,0xd19da4e1,0xec1786eb,0x6fa64971,0x485f7032,0x22cb8755,0xe26d1352,0x33f0b7b3,0x40beeb28,0x2f18a259,0x6747d26b,0x458c553e,0xa7e1466c,0x9411f1df,0x821f750a,0xad07d753,0xca400538,0x8fcc5006,0x282d166a,0xbc3ce7b5,0xe98ba06f,0x448c773c,0x8ecc7204,0x01002202];

        var r = true;
        for(let i = 0;i<52; ++i)
        {
            if(cr.getwi(i) != w[i]){
                console.error(`Assert [${i}]: ${cr.getwi(i).toString(16)} != ${w[i].toString(16)}`);
                r = false;
            }
        }

        if(!r){
            console.error(`key128Expansion() -- failed!`);
            return;
        }   

        console.log(`key128Expansion() -- ok!`);
    }

    static key256Expansion(debug) {
        let key = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4];
        let cr  = new AES(key)
        cr.allowDebugOutput = debug;

        console.dir(`key256Expansion() for object`);
        console.dir(cr);

        let w = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e];

        var r = true;
        for(let i = 0;i<60; ++i)
        {
            if(cr.getwi(i) != w[i]){
                console.error(`Assert [${i}]: ${cr.getwi(i).toString(16)} != ${w[i].toString(16)}`);
                r = false;
            }
        }

        if(!r){
            console.error(`key128Expansion() -- failed!`);
            return;
        }   

        console.log(`key128Expansion() -- ok!`);
    }

    static encrypt128(debug) {
        let key = "000102030405060708090a0b0c0d0e0f";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);     
        let cr  = new AES(keyArray)
        cr.allowDebugOutput = debug;

        console.dir(`encrypt128() for object`);
        console.dir(cr);

        let input = "00112233445566778899aabbccddeeff";
        let inputBuffer = CryptoUtils.hexStringToBuffer(input);  
        let inputArray = new Uint8Array(inputBuffer); 

        console.log("input:",CryptoUtils.bufferToHexString(inputBuffer));
        console.log("key:",CryptoUtils.bufferToHexString(keyBuffer));

        let result = cr.encrypt(inputArray);
        console.log("result:", result);
        result = CryptoUtils.bufferToHexString(result);

        console.log("result:", result);

        if(result != "69c4e0d86a7b0430d8cdb78070b4c55a") {
            console.error(`Assert: ${result} != "69c4e0d86a7b0430d8cdb78070b4c55a"`);
            console.error(`encrypt128() -- failed!`);
            return;
        } 

        console.log(`encrypt128() -- ok!`);
    }

    static encrypt192(debug) {
        let key = "000102030405060708090a0b0c0d0e0f1011121314151617";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);     
        let cr  = new AES(keyArray)
        cr.allowDebugOutput = debug;

        console.dir(`encrypt192() for object`);
        console.dir(cr);

        let input = "00112233445566778899aabbccddeeff";
        let inputBuffer = CryptoUtils.hexStringToBuffer(input);  
        let inputArray = new Uint8Array(inputBuffer); 

        console.log("input:",CryptoUtils.bufferToHexString(inputBuffer));
        console.log("key:",CryptoUtils.bufferToHexString(keyBuffer));

        let result = cr.encrypt(inputArray);
        console.log("result:", result);
        result = CryptoUtils.bufferToHexString(result);

        console.log("result:", result);

        if(result != "dda97ca4864cdfe06eaf70a0ec0d7191") {
            console.error(`Assert: ${result} != "dda97ca4864cdfe06eaf70a0ec0d7191"`);
            console.error(`encrypt192() -- failed!`);
            return;
        } 

        console.log(`encrypt192() -- ok!`);
    }

    static encrypt256(debug) {
        let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);     
        let cr  = new AES(keyArray)
        cr.allowDebugOutput = debug;

        console.dir(`encrypt256() for object`);
        console.dir(cr);

        let input = "00112233445566778899aabbccddeeff";
        let inputBuffer = CryptoUtils.hexStringToBuffer(input);  
        let inputArray = new Uint8Array(inputBuffer); 

        console.log("input:",CryptoUtils.bufferToHexString(inputBuffer));
        console.log("key:",CryptoUtils.bufferToHexString(keyBuffer));

        let result = cr.encrypt(inputArray);
        console.log("result:", result);
        result = CryptoUtils.bufferToHexString(result);

        console.log("result:", result);

        if(result != "8ea2b7ca516745bfeafc49904b496089") {
            console.error(`Assert: ${result} != "8ea2b7ca516745bfeafc49904b496089"`);
            console.error(`encrypt256() -- failed!`);
            return;
        } 

        console.log(`encrypt256() -- ok!`);
    }


    static encryptDecrypt128(debug) {
        let key = "000102030405060708090a0b0c0d0e0f";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);     
        let cr  = new AES(keyArray)
        cr.allowDebugOutput = debug;

        console.dir(`encryptDecrypt128() for object`);
        console.dir(cr);

        let input = "00112233445566778899aabbccddeeff";
        let inputBuffer = CryptoUtils.hexStringToBuffer(input);  
        let inputArray = new Uint8Array(inputBuffer); 

        console.log("input:",CryptoUtils.bufferToHexString(inputBuffer));
        console.log("key:",CryptoUtils.bufferToHexString(keyBuffer));

        console.log(">>> ENCRYPTION");
        let result = cr.encrypt(inputArray);
        let resultArray = new Uint8Array(result); 
        cr.allowDebugOutput = debug;
        console.log(">>> DECRYPTION");
        result = cr.decrypt(resultArray);

        result = CryptoUtils.bufferToHexString(result);

        console.log("result:", result);

        if(result != input) {
            console.error(`Assert: ${result} != ${input}`);
            console.error(`encryptDecrypt128() -- failed!`);
            return;
        } 

        console.log(`encryptDecrypt128() -- ok!`);
    }

    static encryptDecrypt256(debug) {
        let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);     
        let cr  = new AES(keyArray)
        cr.allowDebugOutput = debug;

        console.dir(`encryptDecrypt256() for object`);
        console.dir(cr);

        let input = "00112233445566778899aabbccddeeff";
        let inputBuffer = CryptoUtils.hexStringToBuffer(input);  
        let inputArray = new Uint8Array(inputBuffer); 

        console.log("input:",CryptoUtils.bufferToHexString(inputBuffer));
        console.log("key:",CryptoUtils.bufferToHexString(keyBuffer));

        console.log(">>> ENCRYPTION");
        let result = cr.encrypt(inputArray);
        let resultArray = new Uint8Array(result); 
        cr.allowDebugOutput = debug;
        console.log(">>> DECRYPTION");
        result = cr.decrypt(resultArray);

        result = CryptoUtils.bufferToHexString(result);

        console.log("result:", result);

        if(result != input) {
            console.error(`Assert: ${result} != ${input}`);
            console.error(`encryptDecrypt256() -- failed!`);
            return;
        } 

        console.log(`encryptDecrypt256() -- ok!`);
    }

    static run() {
        AESUnitTest.key128Expansion(false);
        AESUnitTest.key192Expansion(false);
        AESUnitTest.key256Expansion(false);
        AESUnitTest.encrypt128(false);
        AESUnitTest.encrypt192(false);
        AESUnitTest.encrypt256(false);
        AESUnitTest.encryptDecrypt128(false);
        AESUnitTest.encryptDecrypt256(false);
    }
}

class AES_IGE {
    constructor(key, iv) {
        this.aes = new AES(key);
        this.iv = CryptoUtils.cloneArray(iv);
    }

    addPaddingForMessage(bytes) {
        return CryptoUtils.addPadding(bytes, 16);
    }

    decrypt(message) {
        let blockSize = AES.blockSizeByte;
        let fullMessage = CryptoUtils.cloneArray(message);

        while(fullMessage.length % blockSize != 0) {
            fullMessage.push(0x00);
        }

        let xPrev = this.iv.slice(0,blockSize);
        let yPrev = this.iv.slice(blockSize,this.iv.length);

        var decrypted = new ArrayBuffer(fullMessage.length);

        for (let i = 0; i < fullMessage.length; i += blockSize){
            let x = fullMessage.slice(i,i + blockSize);
            let y = CryptoUtils.xorArrays(x, yPrev);
            let buf = this.aes.decrypt(y);
            y = new Uint8Array(buf);
            y = CryptoUtils.xorArrays(y,xPrev);
            xPrev = CryptoUtils.cloneArray(x);
            yPrev = CryptoUtils.cloneArray(y);

            y = new Uint8Array(decrypted);
            y.set(yPrev,i)
        }
        return decrypted;  
    }

    encrypt(message) {
        let blockSize = AES.blockSizeByte;
        let fullMessage = CryptoUtils.cloneArray(message);

        while(fullMessage.length % blockSize != 0) {
            fullMessage.push(0x00);
        }    
        
        let xPrev = this.iv.slice(blockSize,this.iv.length);
        let yPrev = this.iv.slice(0,blockSize);   

        var encrypted = new ArrayBuffer(fullMessage.length); 

        for (let i = 0; i < fullMessage.length; i += blockSize){
            let x = fullMessage.slice(i,i + blockSize);
            let y = CryptoUtils.xorArrays(x, yPrev);
            let buf = this.aes.encrypt(y);
            y = new Uint8Array(buf);
            y = CryptoUtils.xorArrays(y,xPrev);
            xPrev = CryptoUtils.cloneArray(x);
            yPrev = CryptoUtils.cloneArray(y);

            y = new Uint8Array(encrypted);
            y.set(yPrev,i)
        }

        return encrypted;
    }
}

class AES_IGEUnitTest {

    constructor() {}

    static encrypt128_1() {
        console.log(`AES_IGEUnitTest::encrypt128_1()`);

        let key = "000102030405060708090A0B0C0D0E0F";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);

        console.log("key:", key);      

        let iv = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        let ivBuffer = CryptoUtils.hexStringToBuffer(iv);  
        let ivArray = new Uint8Array(ivBuffer);

        console.log("iv:", iv);   

        let message = "0000000000000000000000000000000000000000000000000000000000000000";
        let messageBuffer = CryptoUtils.hexStringToBuffer(message);  
        let messageArray = new Uint8Array(messageBuffer);  

        console.log("message:", message);  

        let aesIge = new AES_IGE(keyArray,ivArray);

        let cipherBuffer = aesIge.encrypt(messageArray);

        let result = CryptoUtils.bufferToHexString(cipherBuffer);
        let input = ("1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB").toLowerCase();

        console.log("result:", result);

        if(result != input) {
            console.error(`Assert: ${result} != ${input}`);
            console.error(`AES_IGEUnitTest::encrypt128_1() -- failed!`);
            return;
        } 

        console.log(`AES_IGEUnitTest::encrypt128_1() -- ok!`);
    }

    static encrypt128_2() {
        console.log(`AES_IGEUnitTest::encrypt128_2()`);

        let key = "5468697320697320616E20696D706C65";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);

        console.log("key:", key);      

        let iv = "6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353";
        let ivBuffer = CryptoUtils.hexStringToBuffer(iv);  
        let ivArray = new Uint8Array(ivBuffer);

        console.log("iv:", iv);   

        let message = "99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B";
        let messageBuffer = CryptoUtils.hexStringToBuffer(message);  
        let messageArray = new Uint8Array(messageBuffer);  

        console.log("message:", message);  

        let aesIge = new AES_IGE(keyArray,ivArray);

        let cipherBuffer = aesIge.encrypt(messageArray);

        let result = CryptoUtils.bufferToHexString(cipherBuffer);
        let input = ("4C2E204C6574277320686F70652042656E20676F74206974207269676874210A").toLowerCase();

        console.log("result:", result);

        if(result != input) {
            console.error(`Assert: ${result} != ${input}`);
            console.error(`AES_IGEUnitTest::encrypt128_2() -- failed!`);
            return;
        } 

        console.log(`AES_IGEUnitTest::encrypt128_2() -- ok!`);
    }

    static decrypt128_2() {
        console.log(`AES_IGEUnitTest::decrypt128_2()`);

        let key = "5468697320697320616E20696D706C65";
        let keyBuffer = CryptoUtils.hexStringToBuffer(key);  
        let keyArray = new Uint8Array(keyBuffer);

        console.log("key:", key);      

        let iv = "6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353";
        let ivBuffer = CryptoUtils.hexStringToBuffer(iv);  
        let ivArray = new Uint8Array(ivBuffer);

        console.log("iv:", iv);   

        let message = "4C2E204C6574277320686F70652042656E20676F74206974207269676874210A";
        let messageBuffer = CryptoUtils.hexStringToBuffer(message);  
        let messageArray = new Uint8Array(messageBuffer);  

        console.log("message:", message);  

        let aesIge = new AES_IGE(keyArray,ivArray);

        let cipherBuffer = aesIge.decrypt(messageArray);

        let result = CryptoUtils.bufferToHexString(cipherBuffer);
        let input = ("99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B").toLowerCase();

        console.log("result:", result);

        if(result != input) {
            console.error(`Assert: ${result} != ${input}`);
            console.error(`AES_IGEUnitTest::decrypt128_2() -- failed!`);
            return;
        } 

        console.log(`AES_IGEUnitTest::decrypt128_2() -- ok!`);
    }

    static run() {
        AES_IGEUnitTest.encrypt128_1();
        AES_IGEUnitTest.encrypt128_2();
        AES_IGEUnitTest.decrypt128_2();
    }
}

class CryptoAlgorithm {
    constructor(){}

    static async hash(algoName, message) {
        if(message instanceof String) {
            message = new Uint8Array(CryptoUtils.hexStringToBuffer(message));            
        } 

        if(message instanceof Array) {
            message = new Uint8Array(message);            
        } 

        return await crypto.subtle.digest(algoName, message);   
    }

    static async sha1(message) {
        return await CryptoAlgorithm.hash('SHA-1', message);   
    }

    static async sha1a(message) {
        return CryptoUtils.cloneArray(new Uint8Array(await CryptoAlgorithm.sha1(message)));
    }

    static async sha256(message) {
        return await CryptoAlgorithm.hash('SHA-256', message);  
    }

    static async sha256a(message) {
        return CryptoUtils.cloneArray(new Uint8Array(await CryptoAlgorithm.sha256(message)));
    }

    static getAesIgeWrapper(key,iv){
        if(key instanceof String) {
            key = new Uint8Array(CryptoUtils.hexStringToBuffer(key));            
        } 

        if(iv instanceof String) {
            iv = new Uint8Array(CryptoUtils.hexStringToBuffer(iv));            
        }

        return new AES_IGE(key,iv);
    }

    static async aesIgeEncrypt(aes, message) {
        if(message instanceof String) {
            message = new Uint8Array(CryptoUtils.hexStringToBuffer(message));            
        } 

        message = aes.addPaddingForMessage(message);

        return new Promise((resolve,reject)=>{
            return resolve(aes.encrypt(message));            
        });
    }

    static async aesIgeDecrypt(aes, message) {
        if(message instanceof String) {
            message = new Uint8Array(CryptoUtils.hexStringToBuffer(message));            
        } 

        return new Promise((resolve,reject)=>{
            return resolve(aes.decrypt(message));            
        });
    }

    static async rsaEncrypt(key,message) {
        message = RSA.addPaddingForMessage(message);
        return new Promise((resolve,reject)=>{
            return resolve(RSA.encrypt(key, message));
        });
    }

    static async rsaDecrypt(key,message) {
        return new Promise((resolve,reject)=>{
            return resolve(RSA.encrypt(key, message));
        });
    }
}

class NumericUtils {
    // Use it with Array data, not with TypedArray
    constructor() {}

    static get radix(){
        return 0xff + 1;
    }

    static get itemBitCount(){
        return 8;
    }

    static get msb(){
        return 128;
    }

    static get lsb(){
        return 0x01;
    }

    /*all next functions work with reverse Arrays*/

    static mpReduceSize(x) {
        if(!x) {
            throw new Error("mpReduceSize incorrect imput");
        } 

        while(x.length > 0) {
            if(x[x.length - 1] == 0) {
                x.pop();
                continue;
            }
            break;
        }  

        if(x.length == 0) {
            x.push(0);
        }    
    }

    static mpEqSize(x,y) {
        if(!x || !y || x.length == 0 || y.length == 0) {
            throw new Error("mpEqSize incorrect imput");
        }

        NumericUtils.mpReduceSize(x);
        NumericUtils.mpReduceSize(y);

        let n = x.length;
        let t = y.length;

        if(n == t){ return; }

        while(n < t) {
            n = x.push(0);
        }

        while(n > t) {
            t = y.push(0);
        }       
    }

    static mpEqSizeTriple(x,y,z) {
        if(!x || !y || !z || 
            x.length == 0 || 
            y.length == 0 || 
            z.length == 0) {
            throw new Error("mpEqSizeTriple incorrect imput");
        }

        NumericUtils.mpReduceSize(x);
        NumericUtils.mpReduceSize(y);
        NumericUtils.mpReduceSize(z);

        let n = x.length;
        let t = y.length;
        let r = z.length;

        if(n == t && t == r){ return; }

        let f = n > t ? n : t;
        f = f > r ? f : r;

        while(n < f) {
            n = x.push(0);
        }

        while(t < f) {
            t = y.push(0);
        }  

        while(r < f) {
            r = z.push(0);
        }        
    }

    static mpPadEnd(x,s) {
        if(!x || s <= 0) {
            throw new Error("mpPadEnd incorrect imput");
        }

        while(x.length < s) { 
            x.push(0);
        }
    }

    //HAC 14.7
    static mpAdd(x,y, debug = false) {
        let b = NumericUtils.radix;
        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        NumericUtils.mpEqSize(x,y);

        let n = x.length - 1;
        let t = y.length - 1; 

        var w = new Array(n + 2);
        let c = 0;

        debug && console.log("mpAdd",x,y);

        for(let i = 0; i <= n; ++i) {
            debug && console.log(`${x[i]} + ${y[i]} + ${c}`);
            let d = x[i] + y[i] + c;
            w[i] = d % b;
            if(d < b) {
                c = 0;
            }
            else {
                c = 1;
            }
            debug && console.log(d,w[i],c);
        }

        w[n+1] = c;    
        NumericUtils.mpReduceSize(w);
        debug && console.log(w);
        return w;
    }

    static mpAddChange(x,y,w) {
        let b = NumericUtils.radix;
        NumericUtils.mpEqSize(x,y);

        let n = x.length - 1;
        let t = y.length - 1; 
        let c = 0;

        for(let i = 0; i <= n; ++i) {
            NumericUtils.mpPadEnd(w,i+1);
            let d = x[i] + y[i] + c;
            w[i] = d % b;
            if(d < b) {
                c = 0;
            }
            else {
                c = 1;
            }
        }
        NumericUtils.mpPadEnd(w,n+2);
        w[n+1] = c;    
        NumericUtils.mpReduceSize(w);
    }

    //HAC 14.9
    static mpSub(x,y, cc = 0, debug = false) {
        let b = NumericUtils.radix;

        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        NumericUtils.mpEqSize(x,y);

        let n = x.length - 1;
        let t = y.length - 1; 

        var w = new Array(n + 1);
        let c = 0;

        debug && console.log("mpSub",x,y);

        for(let i = 0; i <= n; ++i) { 
            debug && console.log(`${b} + ${x[i]} - ${y[i]} + ${c}`); 
            let d = x[i] - y[i] + c;
            if(d >= 0) { 
                c = 0;
            } else {
                d += b;
                c = -1;
            } 
            w[i] = d % b;
            debug && console.log(d,w[i],c);
        }

        if(c == -1 && cc == 0) {
            let nx = new Array(n + 1);
            nx.fill(0);

            return NumericUtils.mpSub(nx,w,c,debug);
        } 

        NumericUtils.mpReduceSize(w);
        debug && console.log(w,c);
        return [w,c];        
    }

    static mpSubChange(x,y,w,cc = 0) {
        let b = NumericUtils.radix;
        NumericUtils.mpEqSize(x,y);

        let n = x.length - 1;
        let t = y.length - 1; 
        let c = 0;

        for(let i = 0; i <= n; ++i) { 
            let d = x[i] - y[i] + c;
            if(d >= 0) { 
                c = 0;
            } else {
                d += b;
                c = -1;
            } 
            w[i] = d % b;
        }

        if(c == -1 && cc == 0) {
            let nx = new Array(n + 1);
            nx.fill(0);

            return NumericUtils.mpSubChange(nx,w,w,c);
        } 

        NumericUtils.mpReduceSize(w);
        return c;        
    }

    static mpLsht(x,digits) {
        for(let i = 0; i < digits; ++i) {
            x.unshift(0);
        }        
    }

    static mpRsht(x,digits) {
        for(let i = 0; i < digits; ++i) {
            x.shift();
        }        
    }

    static mpCmp(x,y) {
        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        NumericUtils.mpReduceSize(x); 
        NumericUtils.mpReduceSize(y); 

        if( x.length < y.length) { return -1; }
        if( x.length > y.length) { return 1; }

        for(let i = x.length-1; i >= 0; --i) {
            if(x[i] < y[i]) { return -1; }
            if(x[i] > y[i]) { return 1; }
        }

        return 0;
    }

    //HAC 14.12
    static mpMult(x,y,debug = false) {
        let n = x.length - 1;
        let t = y.length - 1; 

        var w = new Array(n + t + 1);
        w.fill(0);

        debug && console.log("mpMult",x,y);

        for(let i = 0; i <= t; ++i){
            let c = 0;
            for(let j = 0; j <=n; ++j) {
                let v = w[i+j] + x[j]*y[i] + c;
                debug && console.log(`${w[i+j]} + ${x[j]*y[i]} + ${c}`); 
                w[i+j] = v&0xff;
                c = (v&0xff00) >> 8;
                debug && console.log(i,j,w[i+j],c,(v).toString(16));
            }
            w[n + i + 1] = c;
        }
        NumericUtils.mpReduceSize(w);
        debug && console.log(w);
        return w;
    }

    static mpMultChange(x,y,debug = false) {
        NumericUtils.mpReduceSize(x);
        NumericUtils.mpReduceSize(y);

        if((x.length == 1 && x[0] == 0) ||
           (y.length == 1 && y[0] == 0)) {
            return [0];
        }

        return NumericUtils.mpMult(x,y,debug);
    }

    static mpMult2(x,debug = false) {
        x = CryptoUtils.cloneArray(x);
        let n = x.length - 1;

        debug && console.log("mpMult",x,2);

        let c = 0;
        let l = NumericUtils.lsb;
        let m = NumericUtils.msb;
        let sb = NumericUtils.radix - 1;

        for(let i = 0; i <= n; ++i){
            debug && console.log(`x[${i}] = ${x[i]}, c = ${c}`);
            
            let t = x[i] & m;
            x[i] = ((x[i] << 1) | c) & sb;
            c = t ? l : 0;

            debug && console.log(`x[${i}] = ${x[i]}, c = ${c}`);
        }

        if(c) {
            x.push(c);
        }

        NumericUtils.mpReduceSize(x);
        debug && console.log(x);
        return x;
    }

    //HAC 14.16
    static mpSqr(x,debug = false) {
        x = CryptoUtils.cloneArray(x);
        let t = x.length;
        var w = new Array(2*t);
        w.fill(0);

        for(let i = 0; i < t; ++i) {
            let v = w[2*i] + x[i]*x[i];
            w[2*i] = v&0xff;
            let c = (v&0xff00) >> 8;
            debug && console.log(i,w[2*i],c,(v).toString(16));
            for(let j = i + 1; j < t; ++j) {
                v = w[i+j] + 2*x[j]*x[i] + c;
                w[i+j] = v&0xff;
                c = (v&0xfff00) >> 8;
                debug && console.log(i,j,w[i+j],c,(v).toString(16));
            }
            w[i+t] = c;
        }
        NumericUtils.mpReduceSize(w);
        debug && console.log(w);
        return w;
    }

    //HAC 14.20
    static mpDiv(x,y,debug = false) {
        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        NumericUtils.mpReduceSize(x); 
        NumericUtils.mpReduceSize(y);

        debug && console.log("mpDiv",x,y);

        let n = x.length - 1;
        let t = y.length - 1;

        if(t > n) {
            debug && console.log([0],x);
            return [[0],x];
        }

        if(/*t < 1 || n < 1 ||*/ y[t] == 0) {
            throw new Error("mpDiv incorrect imput");
        }

        let b = NumericUtils.radix;

        var q = new Array(n - t + 1);
        q.fill(0);

        let yb = CryptoUtils.cloneArray(y);
        let xb = CryptoUtils.cloneArray(x);
        NumericUtils.mpLsht(yb,n-t);
        let c = 0;

        while(NumericUtils.mpCmp(xb,yb) >= 0) {
            q[n-t] = q[n-t] + 1;
            c = NumericUtils.mpSubChange(xb,yb,xb,0,debug);
            debug && console.log("yb,xb,c",yb,xb,c);
        }

        debug && console.log("xb,q",xb,q);
        
        for(let i = n; i >= t+1; --i) {
            NumericUtils.mpPadEnd(xb,i + 1);
            debug && console.log("n,t,i,xb,y",n,t,i,xb,y);

            if(xb[i] == y[t]) {
                q[i-t-1] = b - 1;
            } else {
                q[i-t-1] = Math.floor((xb[i]*b+xb[i-1])/y[t]);
            }

            debug && console.log(`q[${i-t-1}]=${q[i-t-1]};`);

            while(q[i-t-1]*(y[t]*b+y[t-1]) > xb[i]*b*b + xb[i-1]*b+xb[i-2]) {
                q[i-t-1] = q[i-t-1] - 1;
            }

            debug && console.log(`q[${i-t-1}]=${q[i-t-1]};`);

            yb = CryptoUtils.cloneArray(y);

            debug && console.log("yb",yb);

            NumericUtils.mpLsht(yb,i-t-1);
            debug && console.log("yb",yb);
            let ybb = CryptoUtils.cloneArray(yb);
            ybb = NumericUtils.mpMultChange(ybb,[q[i-t-1]],debug);
            debug && console.log("ybb",ybb);
            c = NumericUtils.mpSubChange(xb,ybb,xb,0,debug);
            debug && console.log("xb,c",xb,c);

            if(c < 0) {
                c = NumericUtils.mpSubChange(yb,xb,xb,0,debug);
                q[i-t-1] = q[i-t-1] - 1;
            }

            debug && console.log(`q[${i-t-1}]=${q[i-t-1]};`);
        }

        NumericUtils.mpReduceSize(q);
        NumericUtils.mpReduceSize(xb);
        debug && console.log(q,xb);
        return [q,xb];       
    }

    static mpDiv2(x,debug = false) {
        x = CryptoUtils.cloneArray(x);
        NumericUtils.mpReduceSize(x); 
        debug && console.log("mpDiv",x,2);

        let n = x.length - 1;

        if(n < 0) {
            debug && console.log([0]);
            return [0];
        }

        let c = 0;
        let l = NumericUtils.lsb;
        let m = NumericUtils.msb;

        for(let i = n; i >= 0; --i) {
            debug && console.log(`x[${i}] = ${x[i]}, c = ${c}`);
            
            let t = x[i] & l;
            x[i] = (x[i] >> 1) | c;
            c = t ? m : 0;

            debug && console.log(`x[${i}] = ${x[i]}, c = ${c}`);
        }

        NumericUtils.mpReduceSize(x); 
        return x;
    }

    //HAC 14.28
    static mpModMult(x,y,m,debug) {
        var [q,r] = NumericUtils.mpDiv(
            NumericUtils.mpMult(x,y,debug),m,debug);

        return r;
    }

    //HAC 14.28
    static mpModSqr(x,m,debug) {
        var [q,r] = NumericUtils.mpDiv(
            NumericUtils.mpSqr(x,debug),m,debug);

        return r;
    }

    //HAC 14.79
    static mpModPow(g,e,m,debug) {
        var a = [1];
        let t = e.length-1;
        let bc = NumericUtils.itemBitCount - 1;

        debug && console.log("mpModPow: g,e,m",g,e,m);
        debug && console.log("bc,t",bc,t);

        for(let i = t; i >= 0; --i) {
            debug && console.log(`i = ${i}`);
            let k = NumericUtils.msb;
            for(let j = bc; j >= 0; --j) {
                debug && console.log(`j = ${j}`);
                a = NumericUtils.mpModSqr(a,m/*,debug*/);

                debug && console.log(e[i],k);

                if((e[i] & k)) {
                    a = NumericUtils.mpModMult(a,g,m/*,debug*/);
                }

                k = k >> 1;

                debug && console.log("a",a);
            } 
        }

        return a;
    }

    //HAC 14.54
    static mpGcd(x,y,debug) {
        if (NumericUtils.mpCmp(x,y) < 0) {
            //throw new Error("mpGcd: y must be less than x");
            let g = x;
            x = y;
            y = g;
        }

        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        debug && console.log("mpGcd: x,y",x,y);

        let g = [1];

        while(x.length > 0 && y.length > 0 &&
              (x[0] & NumericUtils.lsb) == 0 &&
              (y[0] & NumericUtils.lsb) == 0)
        {
            x = NumericUtils.mpDiv2(x,debug);
            debug && console.log("[x]",x);

            y = NumericUtils.mpDiv2(y,debug);
            debug && console.log("[y]",y);

            g = NumericUtils.mpMult2(g,debug);
            debug && console.log("g",g);
        }

        while(NumericUtils.mpCmp(x,[0]) != 0) {
            while(x.length > 0 && (x[0] & NumericUtils.lsb) == 0) {
                x = NumericUtils.mpDiv2(x,debug);
                debug && console.log("[x]",x);               
            }

            while(y.length > 0 && (y[0] & NumericUtils.lsb) == 0) {
                y = NumericUtils.mpDiv2(y,debug);
                debug && console.log("[y]",y);               
            }

            let [t,] = NumericUtils.mpSub(x,y);
            t = NumericUtils.mpDiv2(t,debug);
            if(NumericUtils.mpCmp(x,y) >= 0) {
                x = t;
            } else {
                y = t;
            }

            debug && console.log("[x,y]",x,y);
        }

        return NumericUtils.mpMultChange(g,y);
    }

    static mpAddC(x,y,sx,sy,debug){
        if(sx == 0 && sy == 0) {
            return [NumericUtils.mpAdd(x,y,debug),0];
        }

        if(sx == 0 && sy == -1) {
            return NumericUtils.mpSub(x,y,debug);
        }

        if(sx == -1 && sy == 0) {
            return NumericUtils.mpSub(y,x,debug);
        }

        if(sx == -1 && sy == -1) {
            return [NumericUtils.mpAdd(x,y,debug),-1];
        }       
    }

    static mpSubC(x,y,sx,sy,debug){
        if(sx == 0 && sy == 0) {
            return NumericUtils.mpSub(x,y,debug);
        }

        if(sx == 0 && sy == -1) {
            return [NumericUtils.mpAdd(x,y,debug),0];
        }

        if(sx == -1 && sy == 0) {
            return [NumericUtils.mpAdd(x,y,debug),-1];
        }

        if(sx == -1 && sy == -1) {
            return NumericUtils.mpSub(y,x,debug);
        }       
    }

    //HAC 14.61
    static mpGcde(x,y,debug) {
        // if (NumericUtils.mpCmp(x,y) < 0) {
        //     //throw new Error("mpGcd: y must be less than x");
        //     let g = x;
        //     x = y;
        //     y = g;
        // }

        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);

        debug && console.log("mpEGCD: x,y",x,y);

        let g = [1];

        while(x.length > 0 && y.length > 0 &&
              (x[0] & NumericUtils.lsb) == 0 &&
              (y[0] & NumericUtils.lsb) == 0)
        {
            x = NumericUtils.mpDiv2(x);
            debug && console.log("[x]",x);

            y = NumericUtils.mpDiv2(y);
            debug && console.log("[y]",y);

            g = NumericUtils.mpMult2(g);
            debug && console.log("g",g);
        }

        let u = x;
        let v = y;
        let A = [1];
        let B = [0];
        let C = [0];
        let D = [1];
        let c = 0;

        let sa = 0;
        let sb = 0;
        let sc = 0;
        let sd = 0;

        debug && console.log("u,v,A,B,C,D",u,v,A,B,C,D); 

        while (NumericUtils.mpCmp(u,[0]) != 0) {

            while(u.length > 0 && (u[0] & NumericUtils.lsb) == 0) {
                u = NumericUtils.mpDiv2(u);
                if(A.length > 0 && (A[0] & NumericUtils.lsb) == 0 &&
                    B.length > 0 && (B[0] & NumericUtils.lsb) == 0) {
                    A = NumericUtils.mpDiv2(A);
                    B = NumericUtils.mpDiv2(B);
                } else {
                    [A,sa] = NumericUtils.mpAddC(A,y,sa,0);
                    A = NumericUtils.mpDiv2(A);

                    [B,sb] = NumericUtils.mpSubC(B,x,sb,0);
                    B = NumericUtils.mpDiv2(B);
                }  

                debug && console.log("A,B",A,B);            
            }

            while(v.length > 0 && (v[0] & NumericUtils.lsb) == 0) {
                v = NumericUtils.mpDiv2(v);
                if(C.length > 0 && (C[0] & NumericUtils.lsb) == 0 &&
                    D.length > 0 && (D[0] & NumericUtils.lsb) == 0) {
                    C = NumericUtils.mpDiv2(C);
                    D = NumericUtils.mpDiv2(D);
                } else {
                    [C,sc] = NumericUtils.mpAddC(C,y,sc,0);
                    C = NumericUtils.mpDiv2(C);

                    [D,sd] = NumericUtils.mpSubC(D,x,sd,0);
                    D = NumericUtils.mpDiv2(D);
                }  
                debug && console.log("C,D",C,D);             
            }

            if(NumericUtils.mpCmp(u,v) >= 0) {
                [u,c] = NumericUtils.mpSub(u,v);
                [A,sa] = NumericUtils.mpSubC(A,C,sa,sc);
                [B,sb] = NumericUtils.mpSubC(B,D,sb,sd);
            } else {
                [v,c] = NumericUtils.mpSub(v,u);
                [C,sc] = NumericUtils.mpSubC(C,A,sc,sa);
                [D,sd] = NumericUtils.mpSubC(D,B,sd,sb);
            }

            debug && console.log("u,v,A,B,C,D",u,v,A,B,C,D); 
        }

        return [C,D,NumericUtils.mpMultChange(g,v)];
    }

    //HAC 14.36
    static mpMontMult(x,y,m,ms,debug) {
        let b = NumericUtils.radix;
        x = CryptoUtils.cloneArray(x);
        y = CryptoUtils.cloneArray(y);
        m = CryptoUtils.cloneArray(m);
        NumericUtils.mpEqSizeTriple(x,y,m);

        let n = x.length - 1;
        let c = 0; 

        var A = new Array(n + 2);
        A.fill(0); 

        debug && console.log("mpMontMult x,y,m,ms",x,y,m,ms); 

        // for(let j = 0; j <= n; ++j){
        //     let u = ((A[0] + x[0]*y[j])*(ms[0]))%b; 
        //     let cs = x[0]*y[j] + A[0] + m[0]*u;
        //     let s = cs&0xff;
        //     c = (cs&0xff00) >> 8;
        //     for(let i = 1; i <= n; ++i) {
        //         cs = c + x[i]*y[j] + A[i] + m[i]*u;
        //         s = cs&0xff;
        //         c = (cs&0xff00) >> 8;
        //         A[i-1] = s;
        //     }
        //     A[n] = c;
        // }

        for(let i = 0; i<=n; ++i) {
            debug && console.log(`i = ${i}`);
            let u = ((A[0] + x[i]*y[0])*(ms[0]))%b; 
            // let u = NumericUtils.mpModMult([A[0] + x[i]*y[0]],ms,[0,1]);
            debug && console.log("u",u);
            let a = NumericUtils.mpMult([x[i]],y);
            debug && console.log("a",a);
            c = NumericUtils.mpMult([u],m);
            debug && console.log("c",c);
            debug && console.log("A",A);
            A = NumericUtils.mpAdd(A,a);
            A = NumericUtils.mpAdd(A,c);
            debug && console.log("A",A);
            NumericUtils.mpRsht(A,1);
            debug && console.log("A",A);
        }   

        if(NumericUtils.mpCmp(A,m) >= 0) {
            [A,c] = NumericUtils.mpSub(A,m);
        }  

        NumericUtils.mpReduceSize(A); 
        debug && console.log("A",A);
        return A;
    }

    //HAC 14.94
    static mpMontModPow(x,e,m,ms,debug) {
        debug && console.log("mpMontModPow x,e,m,ms",x,e,m,ms);

        var A;
        let t = e.length-1;
        let l = m.length;
        let bc = NumericUtils.itemBitCount - 1;
        let R = [1];
        NumericUtils.mpLsht(R,l);
        let R2 = NumericUtils.mpSqr(R);
        let q = 0;
        let r = 0;

        debug && console.log("R2,R,m",R2,R,m);

        [q,r] = NumericUtils.mpDiv(R2,m);
        [q,A] = NumericUtils.mpDiv(R,m);

        let xs = NumericUtils.mpMontMult(x,r,m,ms);

        debug && console.log("xs",xs);
        debug && console.log("A",A);

        for(let i = t; i >= 0; --i) {
            debug && console.log(`i = ${i}`);
            let k = NumericUtils.msb;
            let ex = e[i];
            let flag = 0;

            for(let j = bc; j >= 0; --j, k = k >> 1) {
                if(i == t && !flag){
                    if((ex & k) == 0) {
                        continue;
                    } else {
                        flag = 1;
                    }
                }

                debug && console.log(`j = ${j}`);
                A = NumericUtils.mpMontMult(A,A,m,ms);

                debug && console.log(ex,k);

                if((ex & k)) {
                    A = NumericUtils.mpMontMult(A,xs,m,ms);
                }

                debug && console.log("A",A);
                debug && console.log("k",(k).toString(2));
            } 
        }

        A = NumericUtils.mpMontMult(A,[1],m,ms);

        debug && console.log("A",A);

        return A;
    }

    //HAC 3.9
    static mpFactorize(n, f = 1, debug = false) {
        if(f > 10) {
            throw new Error("mpFactorize: so much f");
        }
        let a = [2];
        let b = [2];

        debug && console.log("mpFactorize:",n);

        while(1) {
            a = NumericUtils.mpSqr(a);
            NumericUtils.mpAddChange(a,[f],a);
            [,a] = NumericUtils.mpDiv(a,n);

            debug && console.log("a",a);

            for(let i = 0; i < 2; ++i) {
                b = NumericUtils.mpSqr(b);
                NumericUtils.mpAddChange(b,[f],b);
                [,b] = NumericUtils.mpDiv(b,n);                
            }

            debug && console.log("b",b);

            let [d,] = NumericUtils.mpSub(a,b);
            debug && console.log("d,n",d,n);
            d = NumericUtils.mpGcd(d,n);
            debug && console.log("d",d);

            if(NumericUtils.mpCmp([1],d) == -1 &&
                NumericUtils.mpCmp(d,n) == -1) {
                let [q,r] = NumericUtils.mpDiv(n,d);

                if(NumericUtils.mpCmp(r,[0]) == 0){
                    return [d,q];
                }
                throw new Error("mpFactorize: incorrect r"); 
            }

            if(NumericUtils.mpCmp(d,n) == 0) {
                ++f;
                return NumericUtils.mpFactorize(n,f);
            }
        }
    }

    /*all next functions work with normal Arrays*/

    static add(x,y, debug = false) {
        return NumericUtils.mpAdd(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug).reverse();
    }

    static sub(x,y, cc = 0, debug = false) {
        let [r,c] = NumericUtils.mpSub(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            cc,debug); 
        return [r.reverse(),c];    
    }

    static cmp(x,y) {
        return NumericUtils.mpCmp(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse());
    }

    static mult(x,y,debug = false) {
        return NumericUtils.mpMult(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug).reverse();
    }

    static div(x,y,debug = false) {
        let [q,r] = NumericUtils.mpDiv(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug);
        return [q.reverse(),r.reverse()];    
    }

    static modMult(x,y,m,debug) {
        return NumericUtils.mpModMult(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug).reverse();
    }

    static modPow(g,e,m,debug) {
        return NumericUtils.mpModPow(
            CryptoUtils.cloneArray(g).reverse(),
            CryptoUtils.cloneArray(e).reverse(),
            CryptoUtils.cloneArray(m).reverse(),
            debug).reverse();
    }

    static gcd(x,y,debug) {
        return NumericUtils.mpGcd(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug).reverse();       
    }

    static modPowMont(g,e,m,ms,debug) {
        return NumericUtils.mpMontModPow(
            CryptoUtils.cloneArray(g).reverse(),
            CryptoUtils.cloneArray(e).reverse(),
            CryptoUtils.cloneArray(m).reverse(),
            CryptoUtils.cloneArray(ms).reverse(),
            debug).reverse();
    }

    static gcde(x,y,debug) {
        return NumericUtils.mpGcde(
            CryptoUtils.cloneArray(x).reverse(),
            CryptoUtils.cloneArray(y).reverse(),
            debug).reverse();       
    }

    static factorize(n, f = 1, debug = false) {
        let [a,b] = NumericUtils.mpFactorize(
            CryptoUtils.cloneArray(n).reverse(),
            f,debug);
        return [a.reverse(),b.reverse()];
    }
}

class NumericUtilsUnitTest {
    constructor() {}

    static mpAddTest() {
        console.log(`NumericUtilsUnitTest::mpAddTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer("24fa92",true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer("22042b0",true))).reverse(); 

        let z = NumericUtils.mpAdd(x,y); 
        let k = new Uint8Array(z.reverse()); 
        let res = "2453d42";
        k = CryptoUtils.bufferToHexString(k,true);  

        console.log("result:", k);

        if(res != k) {
            console.error(`Assert: ${k} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpAddTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpAddTest() -- ok!`);  
    }

    static mpCmpTest(a,b,c) {
        console.log(`NumericUtilsUnitTest::mpCmpTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse(); 

        let res = NumericUtils.mpCmp(x,y); 
        console.log("result:", res);

        if(res != c) {
            console.error(`Assert: ${c} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpCmpTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpCmpTest() -- ok!`);  
    }

    static mpSubTest(a,b,c,debug) {
        console.log(`NumericUtilsUnitTest::mpSubTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse(); 

        let [z,] = NumericUtils.mpSub(x,y,0,debug); 
        let k = new Uint8Array(z.reverse()); 
        let res = (c).toString(16);
        k = CryptoUtils.bufferToHexString(k,true);  

        console.log("result:", k);

        if(res != k) {
            console.error(`Assert: ${k} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpSubTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpSubTest() -- ok!`);  

    }

    static mpMultTest(a,b,c,debug) {
        console.log(`NumericUtilsUnitTest::mpMultTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse(); 

        let z = NumericUtils.mpMult(x,y,debug); 
        let k = new Uint8Array(z.reverse()); 
        let res = (c).toString(16);
        k = CryptoUtils.bufferToHexString(k,true);  

        console.log("result:", k);

        if(res != k) {
            console.error(`Assert: ${k} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpMultTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpMultTest() -- ok!`);  

    }

    static mpMult2Test(a,c,debug) {
        console.log(`NumericUtilsUnitTest::mpMult2Test()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let z = NumericUtils.mpMult2(x,debug); 
        let k = new Uint8Array(z.reverse()); 
        let res = (c).toString(16);
        k = CryptoUtils.bufferToHexString(k,true);  

        console.log("result:", k);

        if(res != k) {
            console.error(`Assert: ${k} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpMult2Test() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpMult2Test() -- ok!`);  

    }

    static mpSqrTest(a,c,debug) {
        console.log(`NumericUtilsUnitTest::mpSqrTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let z = NumericUtils.mpSqr(x,debug); 
        let k = new Uint8Array(z.reverse()); 
        let res = (c).toString(16);
        k = CryptoUtils.bufferToHexString(k,true);  

        console.log("result:", k);

        if(res != k) {
            console.error(`Assert: ${k} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpSqrTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpSqrTest() -- ok!`);  

    }

    static mpDivTest(a,b,c,d,debug) {
        console.log(`NumericUtilsUnitTest::mpDivTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse(); 

        let [q,r] = NumericUtils.mpDiv(x,y,debug); 
        q = CryptoUtils.bufferToHexString(new Uint8Array(q.reverse()),true); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res1 = (c).toString(16);
        let res2 = (d).toString(16);
         

        console.log("result:", q, r);

        if(res1 != q || res2 != r) {
            console.error(`Assert: ${q} != ${res1}`);
            console.error(`Assert: ${r} != ${res2}`);
            console.error(`NumericUtilsUnitTest::mpDivTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpDivTest() -- ok!`);  

    }

    static mpDiv2Test(a,b,debug) {
        console.log(`NumericUtilsUnitTest::mpDiv2Test()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let q = NumericUtils.mpDiv2(x,debug); 
        q = CryptoUtils.bufferToHexString(new Uint8Array(q.reverse()),true); 
        let res1 = (b).toString(16);
         

        console.log("result:", q);

        if(res1 != q) {
            console.error(`Assert: ${q} != ${res1}`);
            console.error(`NumericUtilsUnitTest::mpDiv2Test() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpDiv2Test() -- ok!`);  

    }

    static mpModMultTest(a,b,c,d,debug) {
        console.log(`NumericUtilsUnitTest::mpModMultTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let m = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((c).toString(16),true))).reverse();  

        let r = NumericUtils.mpModMult(x,y,m,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res = (d).toString(16);
         
        console.log("result:", r);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpModMultTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpModMultTest() -- ok!`);  

    }

    static mpModPowTest(a,b,c,d,debug) {
        console.log(`NumericUtilsUnitTest::mpModPowTest()`);

        let g = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let e = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let m = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((c).toString(16),true))).reverse();  

        let r = NumericUtils.mpModPow(g,e,m,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res = (d).toString(16);
         
        console.log("result:", r);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpModPowTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpModPowTest() -- ok!`);  

    }

    static mpMontModPowTest(a,b,c,d,debug) {
        console.log(`NumericUtilsUnitTest::mpMontModPowTest()`);

        let g = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let e = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let m = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((c).toString(16),true))).reverse();

        let [ms,bs,r] = NumericUtils.mpGcde(m,[0,1]); 
        console.log(ms,bs,r);

        r = NumericUtils.mpMontModPow(g,e,m,ms,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res = (d).toString(16);
         
        console.log("result:", r);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpMontModPowTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpMontModPowTest() -- ok!`);  

    }

    static mpMontMultTest(a,b,c,d,debug) {
        console.log(`NumericUtilsUnitTest::mpMontMultTest()`);

        let g = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let e = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let m = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((c).toString(16),true))).reverse();

        let [ms,bs,r] = NumericUtils.mpGcde(m,[0,1]); 
        console.log(ms,bs,r);

        r = NumericUtils.mpMontMult(g,e,m,ms,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res = (d).toString(16);
         
        console.log("result:", r);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpMontMultTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpMontMultTest() -- ok!`);  

    }


    static mpGcdTest(a,b,c,debug) {
        console.log(`NumericUtilsUnitTest::mpGcdTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let r = NumericUtils.mpGcd(x,y,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res = (c).toString(16);
         
        console.log("result:", r);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpGcdTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpGcdTest() -- ok!`);  
    }

    static mpGcdeTest(a,b,c,debug) {
        console.log(`NumericUtilsUnitTest::mpGcdeTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let y = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((b).toString(16),true))).reverse();

        let [A,B,r] = NumericUtils.mpGcde(x,y,debug); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        A = CryptoUtils.bufferToHexString(new Uint8Array(A.reverse()),true);
        B = CryptoUtils.bufferToHexString(new Uint8Array(B.reverse()),true);
        let res = (c).toString(16);
         
        console.log("result v:", r);
        console.log("result A:", A);
        console.log("result B:", B);

        if(res != r) {
            console.error(`Assert: ${r} != ${res}`);
            console.error(`NumericUtilsUnitTest::mpGcdeTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpGcdeTest() -- ok!`);  
    }

    static mpFactorizeTest(a,b,c,debug) {
        console.log(`NumericUtilsUnitTest::mpFactorizeTest()`);

        let x = CryptoUtils.cloneArray(
            new Uint8Array(
                CryptoUtils.hexStringToBuffer((a).toString(16),true))).reverse();

        let [q,r] = NumericUtils.mpFactorize(x,1,debug); 
        q = CryptoUtils.bufferToHexString(new Uint8Array(q.reverse()),true); 
        r = CryptoUtils.bufferToHexString(new Uint8Array(r.reverse()),true);
        let res1 = (b).toString(16);
        let res2 = (c).toString(16);
         

        console.log("result:", q, r);

        if(res1 != q || res2 != r) {
            console.error(`Assert: ${q} != ${res1}`);
            console.error(`Assert: ${r} != ${res2}`);
            console.error(`NumericUtilsUnitTest::mpFactorizeTest() -- failed!`);
            return;
        } 

        console.log(`NumericUtilsUnitTest::mpFactorizeTest() -- ok!`);  

    }

    static run() {
        NumericUtilsUnitTest.mpAddTest();
        NumericUtilsUnitTest.mpSubTest(3996879,4637923,641044,false);
        NumericUtilsUnitTest.mpSubTest(1255453466,342345,1255111121,false);
        NumericUtilsUnitTest.mpCmpTest(111111,111111,0);
        NumericUtilsUnitTest.mpCmpTest(111,111111,-1);
        NumericUtilsUnitTest.mpCmpTest(1111111,111,1);
        NumericUtilsUnitTest.mpMultTest(9274,847,7855078,false);
        NumericUtilsUnitTest.mpMult2Test(123563,247126,false);
        NumericUtilsUnitTest.mpSqrTest(989,978121,false);
        NumericUtilsUnitTest.mpDivTest(721948327,84461,8547,60160,false);
        NumericUtilsUnitTest.mpDiv2Test(2345672,1172836,false);
        NumericUtilsUnitTest.mpModMultTest(123454345345,345,34564325,32484400,false);
        NumericUtilsUnitTest.mpModPowTest(13,14,35679,30031,false);
        NumericUtilsUnitTest.mpModPowTest(6547890621,4532415,76543278906,1039609179,false);
        NumericUtilsUnitTest.mpMontModPowTest(13,14,35679,30031,true);
        NumericUtilsUnitTest.mpMontModPowTest(7,10,13,4,false);
        NumericUtilsUnitTest.mpMontModPowTest(375,249,388,175,true);
        NumericUtilsUnitTest.mpMontMultTest(5792,1229,72639,39796,true);
        NumericUtilsUnitTest.mpGcdTest(1764,868,28,false);
        NumericUtilsUnitTest.mpGcdeTest(1764,868,28,false);
        NumericUtilsUnitTest.mpGcdeTest(693,609,21,false);
        NumericUtilsUnitTest.mpFactorizeTest(455459,743,613,false);
    }
}

class RSA {
    constructor() {}

    static addPaddingForMessage(bytes) {
        return CryptoUtils.addPadding(bytes, 256);
    }

    static encrypt(publicKey, bytes, debug) {
        debug && console.log("pk,mes",publicKey,bytes);

        let B = CryptoUtils.cloneArray(bytes);

        let Nb = CryptoUtils.hexStringToBuffer(publicKey.modulus,true);
        let N = CryptoUtils.cloneArray(new Uint8Array(Nb));

        let Eb = CryptoUtils.hexStringToBuffer(publicKey.exponent,true);
        let E = CryptoUtils.cloneArray(new Uint8Array(Eb));

        let cipher8bitArray = NumericUtils.modPow(B,E,N,debug);

        return (new Uint8Array(cipher8bitArray)).buffer;
    }

    static decrypt(privateKey, bytes, debug) {
        return RSA.encrypt(privateKey,bytes, debug);       
    }
}

class RSAUnitTest {
    constructor(){}   

    static encryptDecryptTest(m,n,e,d,debug) {
        console.log(`RSAUnitTest::encryptDecryptTest()`);

        let message = CryptoUtils.cloneArray(new Uint8Array(
                CryptoUtils.hexStringToBuffer((m).toString(16))));

        let mod = (n).toString(16);

        let expdec = (d).toString(16);

        let expenc = (e).toString(16);

        let chipher = RSA.encrypt({exponent: expenc, modulus:mod}, message,debug);
        
        console.log("chipher-dec",parseInt(CryptoUtils.bufferToHexString(chipher),16));

        let rmessage = RSA.decrypt({exponent: expdec, modulus:mod}, new Uint8Array(chipher), debug);

        console.log("res-message-dec",parseInt(CryptoUtils.bufferToHexString(rmessage),16));

        let r = CryptoUtils.bufferToHexString(rmessage);

        console.log("message:", message);
        console.log("chipher:", chipher);        
        console.log("result:", r);

        if((m).toString(16) != r) {
            console.error(`Assert: ${r} != ${(m).toString(16)}`);
            console.error(`RSAUnitTest::encryptDecryptTest() -- failed!`);
            return;
        } 

        console.log(`RSAUnitTest::encryptDecryptTest() -- ok!`);  

    } 

    static run() {
        RSAUnitTest.encryptDecryptTest(5234673,6012707,3674911,422191,false);
    }
}

class Tgm {
    constructor(){
        this.API = {"constructors":[{"id":"-1132882121","predicate":"boolFalse","params":[],"type":"Bool"},{"id":"-1720552011","predicate":"boolTrue","params":[],"type":"Bool"},{"id":"1072550713","predicate":"true","params":[],"type":"True"},{"id":"481674261","predicate":"vector","params":[],"type":"Vector t"},{"id":"-994444869","predicate":"error","params":[{"name":"code","type":"int"},{"name":"text","type":"string"}],"type":"Error"},{"id":"1450380236","predicate":"null","params":[],"type":"Null"},{"id":"2134579434","predicate":"inputPeerEmpty","params":[],"type":"InputPeer"},{"id":"2107670217","predicate":"inputPeerSelf","params":[],"type":"InputPeer"},{"id":"396093539","predicate":"inputPeerChat","params":[{"name":"chat_id","type":"int"}],"type":"InputPeer"},{"id":"-1182234929","predicate":"inputUserEmpty","params":[],"type":"InputUser"},{"id":"-138301121","predicate":"inputUserSelf","params":[],"type":"InputUser"},{"id":"-208488460","predicate":"inputPhoneContact","params":[{"name":"client_id","type":"long"},{"name":"phone","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"}],"type":"InputContact"},{"id":"-181407105","predicate":"inputFile","params":[{"name":"id","type":"long"},{"name":"parts","type":"int"},{"name":"name","type":"string"},{"name":"md5_checksum","type":"string"}],"type":"InputFile"},{"id":"-1771768449","predicate":"inputMediaEmpty","params":[],"type":"InputMedia"},{"id":"505969924","predicate":"inputMediaUploadedPhoto","params":[{"name":"flags","type":"#"},{"name":"file","type":"InputFile"},{"name":"stickers","type":"flags.0?Vector<InputDocument>"},{"name":"ttl_seconds","type":"flags.1?int"}],"type":"InputMedia"},{"id":"-1279654347","predicate":"inputMediaPhoto","params":[{"name":"flags","type":"#"},{"name":"id","type":"InputPhoto"},{"name":"ttl_seconds","type":"flags.0?int"}],"type":"InputMedia"},{"id":"-104578748","predicate":"inputMediaGeoPoint","params":[{"name":"geo_point","type":"InputGeoPoint"}],"type":"InputMedia"},{"id":"-122978821","predicate":"inputMediaContact","params":[{"name":"phone_number","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"vcard","type":"string"}],"type":"InputMedia"},{"id":"480546647","predicate":"inputChatPhotoEmpty","params":[],"type":"InputChatPhoto"},{"id":"-1837345356","predicate":"inputChatUploadedPhoto","params":[{"name":"file","type":"InputFile"}],"type":"InputChatPhoto"},{"id":"-1991004873","predicate":"inputChatPhoto","params":[{"name":"id","type":"InputPhoto"}],"type":"InputChatPhoto"},{"id":"-457104426","predicate":"inputGeoPointEmpty","params":[],"type":"InputGeoPoint"},{"id":"-206066487","predicate":"inputGeoPoint","params":[{"name":"lat","type":"double"},{"name":"long","type":"double"}],"type":"InputGeoPoint"},{"id":"483901197","predicate":"inputPhotoEmpty","params":[],"type":"InputPhoto"},{"id":"1001634122","predicate":"inputPhoto","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"}],"type":"InputPhoto"},{"id":"-539317279","predicate":"inputFileLocation","params":[{"name":"volume_id","type":"long"},{"name":"local_id","type":"int"},{"name":"secret","type":"long"},{"name":"file_reference","type":"bytes"}],"type":"InputFileLocation"},{"id":"-1649296275","predicate":"peerUser","params":[{"name":"user_id","type":"int"}],"type":"Peer"},{"id":"-1160714821","predicate":"peerChat","params":[{"name":"chat_id","type":"int"}],"type":"Peer"},{"id":"-1432995067","predicate":"storage.fileUnknown","params":[],"type":"storage.FileType"},{"id":"1086091090","predicate":"storage.filePartial","params":[],"type":"storage.FileType"},{"id":"8322574","predicate":"storage.fileJpeg","params":[],"type":"storage.FileType"},{"id":"-891180321","predicate":"storage.fileGif","params":[],"type":"storage.FileType"},{"id":"172975040","predicate":"storage.filePng","params":[],"type":"storage.FileType"},{"id":"-1373745011","predicate":"storage.filePdf","params":[],"type":"storage.FileType"},{"id":"1384777335","predicate":"storage.fileMp3","params":[],"type":"storage.FileType"},{"id":"1258941372","predicate":"storage.fileMov","params":[],"type":"storage.FileType"},{"id":"-1278304028","predicate":"storage.fileMp4","params":[],"type":"storage.FileType"},{"id":"276907596","predicate":"storage.fileWebp","params":[],"type":"storage.FileType"},{"id":"537022650","predicate":"userEmpty","params":[{"name":"id","type":"int"}],"type":"User"},{"id":"1326562017","predicate":"userProfilePhotoEmpty","params":[],"type":"UserProfilePhoto"},{"id":"-321430132","predicate":"userProfilePhoto","params":[{"name":"photo_id","type":"long"},{"name":"photo_small","type":"FileLocation"},{"name":"photo_big","type":"FileLocation"},{"name":"dc_id","type":"int"}],"type":"UserProfilePhoto"},{"id":"164646985","predicate":"userStatusEmpty","params":[],"type":"UserStatus"},{"id":"-306628279","predicate":"userStatusOnline","params":[{"name":"expires","type":"int"}],"type":"UserStatus"},{"id":"9203775","predicate":"userStatusOffline","params":[{"name":"was_online","type":"int"}],"type":"UserStatus"},{"id":"-1683826688","predicate":"chatEmpty","params":[{"name":"id","type":"int"}],"type":"Chat"},{"id":"1004149726","predicate":"chat","params":[{"name":"flags","type":"#"},{"name":"creator","type":"flags.0?true"},{"name":"kicked","type":"flags.1?true"},{"name":"left","type":"flags.2?true"},{"name":"deactivated","type":"flags.5?true"},{"name":"id","type":"int"},{"name":"title","type":"string"},{"name":"photo","type":"ChatPhoto"},{"name":"participants_count","type":"int"},{"name":"date","type":"int"},{"name":"version","type":"int"},{"name":"migrated_to","type":"flags.6?InputChannel"},{"name":"admin_rights","type":"flags.14?ChatAdminRights"},{"name":"default_banned_rights","type":"flags.18?ChatBannedRights"}],"type":"Chat"},{"id":"120753115","predicate":"chatForbidden","params":[{"name":"id","type":"int"},{"name":"title","type":"string"}],"type":"Chat"},{"id":"461151667","predicate":"chatFull","params":[{"name":"flags","type":"#"},{"name":"can_set_username","type":"flags.7?true"},{"name":"has_scheduled","type":"flags.8?true"},{"name":"id","type":"int"},{"name":"about","type":"string"},{"name":"participants","type":"ChatParticipants"},{"name":"chat_photo","type":"flags.2?Photo"},{"name":"notify_settings","type":"PeerNotifySettings"},{"name":"exported_invite","type":"ExportedChatInvite"},{"name":"bot_info","type":"flags.3?Vector<BotInfo>"},{"name":"pinned_msg_id","type":"flags.6?int"},{"name":"folder_id","type":"flags.11?int"}],"type":"ChatFull"},{"id":"-925415106","predicate":"chatParticipant","params":[{"name":"user_id","type":"int"},{"name":"inviter_id","type":"int"},{"name":"date","type":"int"}],"type":"ChatParticipant"},{"id":"-57668565","predicate":"chatParticipantsForbidden","params":[{"name":"flags","type":"#"},{"name":"chat_id","type":"int"},{"name":"self_participant","type":"flags.0?ChatParticipant"}],"type":"ChatParticipants"},{"id":"1061556205","predicate":"chatParticipants","params":[{"name":"chat_id","type":"int"},{"name":"participants","type":"Vector<ChatParticipant>"},{"name":"version","type":"int"}],"type":"ChatParticipants"},{"id":"935395612","predicate":"chatPhotoEmpty","params":[],"type":"ChatPhoto"},{"id":"1197267925","predicate":"chatPhoto","params":[{"name":"photo_small","type":"FileLocation"},{"name":"photo_big","type":"FileLocation"},{"name":"dc_id","type":"int"}],"type":"ChatPhoto"},{"id":"-2082087340","predicate":"messageEmpty","params":[{"name":"id","type":"int"}],"type":"Message"},{"id":"1160515173","predicate":"message","params":[{"name":"flags","type":"#"},{"name":"out","type":"flags.1?true"},{"name":"mentioned","type":"flags.4?true"},{"name":"media_unread","type":"flags.5?true"},{"name":"silent","type":"flags.13?true"},{"name":"post","type":"flags.14?true"},{"name":"from_scheduled","type":"flags.18?true"},{"name":"legacy","type":"flags.19?true"},{"name":"edit_hide","type":"flags.21?true"},{"name":"id","type":"int"},{"name":"from_id","type":"flags.8?int"},{"name":"to_id","type":"Peer"},{"name":"fwd_from","type":"flags.2?MessageFwdHeader"},{"name":"via_bot_id","type":"flags.11?int"},{"name":"reply_to_msg_id","type":"flags.3?int"},{"name":"date","type":"int"},{"name":"message","type":"string"},{"name":"media","type":"flags.9?MessageMedia"},{"name":"reply_markup","type":"flags.6?ReplyMarkup"},{"name":"entities","type":"flags.7?Vector<MessageEntity>"},{"name":"views","type":"flags.10?int"},{"name":"edit_date","type":"flags.15?int"},{"name":"post_author","type":"flags.16?string"},{"name":"grouped_id","type":"flags.17?long"},{"name":"restriction_reason","type":"flags.22?Vector<RestrictionReason>"}],"type":"Message"},{"id":"-1642487306","predicate":"messageService","params":[{"name":"flags","type":"#"},{"name":"out","type":"flags.1?true"},{"name":"mentioned","type":"flags.4?true"},{"name":"media_unread","type":"flags.5?true"},{"name":"silent","type":"flags.13?true"},{"name":"post","type":"flags.14?true"},{"name":"legacy","type":"flags.19?true"},{"name":"id","type":"int"},{"name":"from_id","type":"flags.8?int"},{"name":"to_id","type":"Peer"},{"name":"reply_to_msg_id","type":"flags.3?int"},{"name":"date","type":"int"},{"name":"action","type":"MessageAction"}],"type":"Message"},{"id":"1038967584","predicate":"messageMediaEmpty","params":[],"type":"MessageMedia"},{"id":"1766936791","predicate":"messageMediaPhoto","params":[{"name":"flags","type":"#"},{"name":"photo","type":"flags.0?Photo"},{"name":"ttl_seconds","type":"flags.2?int"}],"type":"MessageMedia"},{"id":"1457575028","predicate":"messageMediaGeo","params":[{"name":"geo","type":"GeoPoint"}],"type":"MessageMedia"},{"id":"-873313984","predicate":"messageMediaContact","params":[{"name":"phone_number","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"vcard","type":"string"},{"name":"user_id","type":"int"}],"type":"MessageMedia"},{"id":"-1618676578","predicate":"messageMediaUnsupported","params":[],"type":"MessageMedia"},{"id":"-1230047312","predicate":"messageActionEmpty","params":[],"type":"MessageAction"},{"id":"-1503425638","predicate":"messageActionChatCreate","params":[{"name":"title","type":"string"},{"name":"users","type":"Vector<int>"}],"type":"MessageAction"},{"id":"-1247687078","predicate":"messageActionChatEditTitle","params":[{"name":"title","type":"string"}],"type":"MessageAction"},{"id":"2144015272","predicate":"messageActionChatEditPhoto","params":[{"name":"photo","type":"Photo"}],"type":"MessageAction"},{"id":"-1780220945","predicate":"messageActionChatDeletePhoto","params":[],"type":"MessageAction"},{"id":"1217033015","predicate":"messageActionChatAddUser","params":[{"name":"users","type":"Vector<int>"}],"type":"MessageAction"},{"id":"-1297179892","predicate":"messageActionChatDeleteUser","params":[{"name":"user_id","type":"int"}],"type":"MessageAction"},{"id":"739712882","predicate":"dialog","params":[{"name":"flags","type":"#"},{"name":"pinned","type":"flags.2?true"},{"name":"unread_mark","type":"flags.3?true"},{"name":"peer","type":"Peer"},{"name":"top_message","type":"int"},{"name":"read_inbox_max_id","type":"int"},{"name":"read_outbox_max_id","type":"int"},{"name":"unread_count","type":"int"},{"name":"unread_mentions_count","type":"int"},{"name":"notify_settings","type":"PeerNotifySettings"},{"name":"pts","type":"flags.0?int"},{"name":"draft","type":"flags.1?DraftMessage"},{"name":"folder_id","type":"flags.4?int"}],"type":"Dialog"},{"id":"590459437","predicate":"photoEmpty","params":[{"name":"id","type":"long"}],"type":"Photo"},{"id":"-797637467","predicate":"photo","params":[{"name":"flags","type":"#"},{"name":"has_stickers","type":"flags.0?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"},{"name":"date","type":"int"},{"name":"sizes","type":"Vector<PhotoSize>"},{"name":"dc_id","type":"int"}],"type":"Photo"},{"id":"236446268","predicate":"photoSizeEmpty","params":[{"name":"type","type":"string"}],"type":"PhotoSize"},{"id":"2009052699","predicate":"photoSize","params":[{"name":"type","type":"string"},{"name":"location","type":"FileLocation"},{"name":"w","type":"int"},{"name":"h","type":"int"},{"name":"size","type":"int"}],"type":"PhotoSize"},{"id":"-374917894","predicate":"photoCachedSize","params":[{"name":"type","type":"string"},{"name":"location","type":"FileLocation"},{"name":"w","type":"int"},{"name":"h","type":"int"},{"name":"bytes","type":"bytes"}],"type":"PhotoSize"},{"id":"286776671","predicate":"geoPointEmpty","params":[],"type":"GeoPoint"},{"id":"43446532","predicate":"geoPoint","params":[{"name":"long","type":"double"},{"name":"lat","type":"double"},{"name":"access_hash","type":"long"}],"type":"GeoPoint"},{"id":"1577067778","predicate":"auth.sentCode","params":[{"name":"flags","type":"#"},{"name":"type","type":"auth.SentCodeType"},{"name":"phone_code_hash","type":"string"},{"name":"next_type","type":"flags.1?auth.CodeType"},{"name":"timeout","type":"flags.2?int"}],"type":"auth.SentCode"},{"id":"-855308010","predicate":"auth.authorization","params":[{"name":"flags","type":"#"},{"name":"tmp_sessions","type":"flags.0?int"},{"name":"user","type":"User"}],"type":"auth.Authorization"},{"id":"-543777747","predicate":"auth.exportedAuthorization","params":[{"name":"id","type":"int"},{"name":"bytes","type":"bytes"}],"type":"auth.ExportedAuthorization"},{"id":"-1195615476","predicate":"inputNotifyPeer","params":[{"name":"peer","type":"InputPeer"}],"type":"InputNotifyPeer"},{"id":"423314455","predicate":"inputNotifyUsers","params":[],"type":"InputNotifyPeer"},{"id":"1251338318","predicate":"inputNotifyChats","params":[],"type":"InputNotifyPeer"},{"id":"-1673717362","predicate":"inputPeerNotifySettings","params":[{"name":"flags","type":"#"},{"name":"show_previews","type":"flags.0?Bool"},{"name":"silent","type":"flags.1?Bool"},{"name":"mute_until","type":"flags.2?int"},{"name":"sound","type":"flags.3?string"}],"type":"InputPeerNotifySettings"},{"id":"-1353671392","predicate":"peerNotifySettings","params":[{"name":"flags","type":"#"},{"name":"show_previews","type":"flags.0?Bool"},{"name":"silent","type":"flags.1?Bool"},{"name":"mute_until","type":"flags.2?int"},{"name":"sound","type":"flags.3?string"}],"type":"PeerNotifySettings"},{"id":"-2122045747","predicate":"peerSettings","params":[{"name":"flags","type":"#"},{"name":"report_spam","type":"flags.0?true"},{"name":"add_contact","type":"flags.1?true"},{"name":"block_contact","type":"flags.2?true"},{"name":"share_contact","type":"flags.3?true"},{"name":"need_contacts_exception","type":"flags.4?true"},{"name":"report_geo","type":"flags.5?true"}],"type":"PeerSettings"},{"id":"-1539849235","predicate":"wallPaper","params":[{"name":"id","type":"long"},{"name":"flags","type":"#"},{"name":"creator","type":"flags.0?true"},{"name":"default","type":"flags.1?true"},{"name":"pattern","type":"flags.3?true"},{"name":"dark","type":"flags.4?true"},{"name":"access_hash","type":"long"},{"name":"slug","type":"string"},{"name":"document","type":"Document"},{"name":"settings","type":"flags.2?WallPaperSettings"}],"type":"WallPaper"},{"id":"1490799288","predicate":"inputReportReasonSpam","params":[],"type":"ReportReason"},{"id":"505595789","predicate":"inputReportReasonViolence","params":[],"type":"ReportReason"},{"id":"777640226","predicate":"inputReportReasonPornography","params":[],"type":"ReportReason"},{"id":"-1376497949","predicate":"inputReportReasonChildAbuse","params":[],"type":"ReportReason"},{"id":"-512463606","predicate":"inputReportReasonOther","params":[{"name":"text","type":"string"}],"type":"ReportReason"},{"id":"-302941166","predicate":"userFull","params":[{"name":"flags","type":"#"},{"name":"blocked","type":"flags.0?true"},{"name":"phone_calls_available","type":"flags.4?true"},{"name":"phone_calls_private","type":"flags.5?true"},{"name":"can_pin_message","type":"flags.7?true"},{"name":"has_scheduled","type":"flags.12?true"},{"name":"user","type":"User"},{"name":"about","type":"flags.1?string"},{"name":"settings","type":"PeerSettings"},{"name":"profile_photo","type":"flags.2?Photo"},{"name":"notify_settings","type":"PeerNotifySettings"},{"name":"bot_info","type":"flags.3?BotInfo"},{"name":"pinned_msg_id","type":"flags.6?int"},{"name":"common_chats_count","type":"int"},{"name":"folder_id","type":"flags.11?int"}],"type":"UserFull"},{"id":"-116274796","predicate":"contact","params":[{"name":"user_id","type":"int"},{"name":"mutual","type":"Bool"}],"type":"Contact"},{"id":"-805141448","predicate":"importedContact","params":[{"name":"user_id","type":"int"},{"name":"client_id","type":"long"}],"type":"ImportedContact"},{"id":"1444661369","predicate":"contactBlocked","params":[{"name":"user_id","type":"int"},{"name":"date","type":"int"}],"type":"ContactBlocked"},{"id":"-748155807","predicate":"contactStatus","params":[{"name":"user_id","type":"int"},{"name":"status","type":"UserStatus"}],"type":"ContactStatus"},{"id":"-1219778094","predicate":"contacts.contactsNotModified","params":[],"type":"contacts.Contacts"},{"id":"-353862078","predicate":"contacts.contacts","params":[{"name":"contacts","type":"Vector<Contact>"},{"name":"saved_count","type":"int"},{"name":"users","type":"Vector<User>"}],"type":"contacts.Contacts"},{"id":"2010127419","predicate":"contacts.importedContacts","params":[{"name":"imported","type":"Vector<ImportedContact>"},{"name":"popular_invites","type":"Vector<PopularContact>"},{"name":"retry_contacts","type":"Vector<long>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.ImportedContacts"},{"id":"471043349","predicate":"contacts.blocked","params":[{"name":"blocked","type":"Vector<ContactBlocked>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.Blocked"},{"id":"-1878523231","predicate":"contacts.blockedSlice","params":[{"name":"count","type":"int"},{"name":"blocked","type":"Vector<ContactBlocked>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.Blocked"},{"id":"364538944","predicate":"messages.dialogs","params":[{"name":"dialogs","type":"Vector<Dialog>"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.Dialogs"},{"id":"1910543603","predicate":"messages.dialogsSlice","params":[{"name":"count","type":"int"},{"name":"dialogs","type":"Vector<Dialog>"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.Dialogs"},{"id":"-1938715001","predicate":"messages.messages","params":[{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.Messages"},{"id":"-923939298","predicate":"messages.messagesSlice","params":[{"name":"flags","type":"#"},{"name":"inexact","type":"flags.1?true"},{"name":"count","type":"int"},{"name":"next_rate","type":"flags.0?int"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.Messages"},{"id":"1694474197","predicate":"messages.chats","params":[{"name":"chats","type":"Vector<Chat>"}],"type":"messages.Chats"},{"id":"-438840932","predicate":"messages.chatFull","params":[{"name":"full_chat","type":"ChatFull"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.ChatFull"},{"id":"-1269012015","predicate":"messages.affectedHistory","params":[{"name":"pts","type":"int"},{"name":"pts_count","type":"int"},{"name":"offset","type":"int"}],"type":"messages.AffectedHistory"},{"id":"1474492012","predicate":"inputMessagesFilterEmpty","params":[],"type":"MessagesFilter"},{"id":"-1777752804","predicate":"inputMessagesFilterPhotos","params":[],"type":"MessagesFilter"},{"id":"-1614803355","predicate":"inputMessagesFilterVideo","params":[],"type":"MessagesFilter"},{"id":"1458172132","predicate":"inputMessagesFilterPhotoVideo","params":[],"type":"MessagesFilter"},{"id":"-1629621880","predicate":"inputMessagesFilterDocument","params":[],"type":"MessagesFilter"},{"id":"2129714567","predicate":"inputMessagesFilterUrl","params":[],"type":"MessagesFilter"},{"id":"-3644025","predicate":"inputMessagesFilterGif","params":[],"type":"MessagesFilter"},{"id":"522914557","predicate":"updateNewMessage","params":[{"name":"message","type":"Message"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"1318109142","predicate":"updateMessageID","params":[{"name":"id","type":"int"},{"name":"random_id","type":"long"}],"type":"Update"},{"id":"-1576161051","predicate":"updateDeleteMessages","params":[{"name":"messages","type":"Vector<int>"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"1548249383","predicate":"updateUserTyping","params":[{"name":"user_id","type":"int"},{"name":"action","type":"SendMessageAction"}],"type":"Update"},{"id":"-1704596961","predicate":"updateChatUserTyping","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"int"},{"name":"action","type":"SendMessageAction"}],"type":"Update"},{"id":"125178264","predicate":"updateChatParticipants","params":[{"name":"participants","type":"ChatParticipants"}],"type":"Update"},{"id":"469489699","predicate":"updateUserStatus","params":[{"name":"user_id","type":"int"},{"name":"status","type":"UserStatus"}],"type":"Update"},{"id":"-1489818765","predicate":"updateUserName","params":[{"name":"user_id","type":"int"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"username","type":"string"}],"type":"Update"},{"id":"-1791935732","predicate":"updateUserPhoto","params":[{"name":"user_id","type":"int"},{"name":"date","type":"int"},{"name":"photo","type":"UserProfilePhoto"},{"name":"previous","type":"Bool"}],"type":"Update"},{"id":"-1519637954","predicate":"updates.state","params":[{"name":"pts","type":"int"},{"name":"qts","type":"int"},{"name":"date","type":"int"},{"name":"seq","type":"int"},{"name":"unread_count","type":"int"}],"type":"updates.State"},{"id":"1567990072","predicate":"updates.differenceEmpty","params":[{"name":"date","type":"int"},{"name":"seq","type":"int"}],"type":"updates.Difference"},{"id":"16030880","predicate":"updates.difference","params":[{"name":"new_messages","type":"Vector<Message>"},{"name":"new_encrypted_messages","type":"Vector<EncryptedMessage>"},{"name":"other_updates","type":"Vector<Update>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"},{"name":"state","type":"updates.State"}],"type":"updates.Difference"},{"id":"-1459938943","predicate":"updates.differenceSlice","params":[{"name":"new_messages","type":"Vector<Message>"},{"name":"new_encrypted_messages","type":"Vector<EncryptedMessage>"},{"name":"other_updates","type":"Vector<Update>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"},{"name":"intermediate_state","type":"updates.State"}],"type":"updates.Difference"},{"id":"-484987010","predicate":"updatesTooLong","params":[],"type":"Updates"},{"id":"-1857044719","predicate":"updateShortMessage","params":[{"name":"flags","type":"#"},{"name":"out","type":"flags.1?true"},{"name":"mentioned","type":"flags.4?true"},{"name":"media_unread","type":"flags.5?true"},{"name":"silent","type":"flags.13?true"},{"name":"id","type":"int"},{"name":"user_id","type":"int"},{"name":"message","type":"string"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"},{"name":"date","type":"int"},{"name":"fwd_from","type":"flags.2?MessageFwdHeader"},{"name":"via_bot_id","type":"flags.11?int"},{"name":"reply_to_msg_id","type":"flags.3?int"},{"name":"entities","type":"flags.7?Vector<MessageEntity>"}],"type":"Updates"},{"id":"377562760","predicate":"updateShortChatMessage","params":[{"name":"flags","type":"#"},{"name":"out","type":"flags.1?true"},{"name":"mentioned","type":"flags.4?true"},{"name":"media_unread","type":"flags.5?true"},{"name":"silent","type":"flags.13?true"},{"name":"id","type":"int"},{"name":"from_id","type":"int"},{"name":"chat_id","type":"int"},{"name":"message","type":"string"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"},{"name":"date","type":"int"},{"name":"fwd_from","type":"flags.2?MessageFwdHeader"},{"name":"via_bot_id","type":"flags.11?int"},{"name":"reply_to_msg_id","type":"flags.3?int"},{"name":"entities","type":"flags.7?Vector<MessageEntity>"}],"type":"Updates"},{"id":"2027216577","predicate":"updateShort","params":[{"name":"update","type":"Update"},{"name":"date","type":"int"}],"type":"Updates"},{"id":"1918567619","predicate":"updatesCombined","params":[{"name":"updates","type":"Vector<Update>"},{"name":"users","type":"Vector<User>"},{"name":"chats","type":"Vector<Chat>"},{"name":"date","type":"int"},{"name":"seq_start","type":"int"},{"name":"seq","type":"int"}],"type":"Updates"},{"id":"1957577280","predicate":"updates","params":[{"name":"updates","type":"Vector<Update>"},{"name":"users","type":"Vector<User>"},{"name":"chats","type":"Vector<Chat>"},{"name":"date","type":"int"},{"name":"seq","type":"int"}],"type":"Updates"},{"id":"-1916114267","predicate":"photos.photos","params":[{"name":"photos","type":"Vector<Photo>"},{"name":"users","type":"Vector<User>"}],"type":"photos.Photos"},{"id":"352657236","predicate":"photos.photosSlice","params":[{"name":"count","type":"int"},{"name":"photos","type":"Vector<Photo>"},{"name":"users","type":"Vector<User>"}],"type":"photos.Photos"},{"id":"539045032","predicate":"photos.photo","params":[{"name":"photo","type":"Photo"},{"name":"users","type":"Vector<User>"}],"type":"photos.Photo"},{"id":"157948117","predicate":"upload.file","params":[{"name":"type","type":"storage.FileType"},{"name":"mtime","type":"int"},{"name":"bytes","type":"bytes"}],"type":"upload.File"},{"id":"414687501","predicate":"dcOption","params":[{"name":"flags","type":"#"},{"name":"ipv6","type":"flags.0?true"},{"name":"media_only","type":"flags.1?true"},{"name":"tcpo_only","type":"flags.2?true"},{"name":"cdn","type":"flags.3?true"},{"name":"static","type":"flags.4?true"},{"name":"id","type":"int"},{"name":"ip_address","type":"string"},{"name":"port","type":"int"},{"name":"secret","type":"flags.10?bytes"}],"type":"DcOption"},{"id":"856375399","predicate":"config","params":[{"name":"flags","type":"#"},{"name":"phonecalls_enabled","type":"flags.1?true"},{"name":"default_p2p_contacts","type":"flags.3?true"},{"name":"preload_featured_stickers","type":"flags.4?true"},{"name":"ignore_phone_entities","type":"flags.5?true"},{"name":"revoke_pm_inbox","type":"flags.6?true"},{"name":"blocked_mode","type":"flags.8?true"},{"name":"pfs_enabled","type":"flags.13?true"},{"name":"date","type":"int"},{"name":"expires","type":"int"},{"name":"test_mode","type":"Bool"},{"name":"this_dc","type":"int"},{"name":"dc_options","type":"Vector<DcOption>"},{"name":"dc_txt_domain_name","type":"string"},{"name":"chat_size_max","type":"int"},{"name":"megagroup_size_max","type":"int"},{"name":"forwarded_count_max","type":"int"},{"name":"online_update_period_ms","type":"int"},{"name":"offline_blur_timeout_ms","type":"int"},{"name":"offline_idle_timeout_ms","type":"int"},{"name":"online_cloud_timeout_ms","type":"int"},{"name":"notify_cloud_delay_ms","type":"int"},{"name":"notify_default_delay_ms","type":"int"},{"name":"push_chat_period_ms","type":"int"},{"name":"push_chat_limit","type":"int"},{"name":"saved_gifs_limit","type":"int"},{"name":"edit_time_limit","type":"int"},{"name":"revoke_time_limit","type":"int"},{"name":"revoke_pm_time_limit","type":"int"},{"name":"rating_e_decay","type":"int"},{"name":"stickers_recent_limit","type":"int"},{"name":"stickers_faved_limit","type":"int"},{"name":"channels_read_media_period","type":"int"},{"name":"tmp_sessions","type":"flags.0?int"},{"name":"pinned_dialogs_count_max","type":"int"},{"name":"pinned_infolder_count_max","type":"int"},{"name":"call_receive_timeout_ms","type":"int"},{"name":"call_ring_timeout_ms","type":"int"},{"name":"call_connect_timeout_ms","type":"int"},{"name":"call_packet_timeout_ms","type":"int"},{"name":"me_url_prefix","type":"string"},{"name":"autoupdate_url_prefix","type":"flags.7?string"},{"name":"gif_search_username","type":"flags.9?string"},{"name":"venue_search_username","type":"flags.10?string"},{"name":"img_search_username","type":"flags.11?string"},{"name":"static_maps_provider","type":"flags.12?string"},{"name":"caption_length_max","type":"int"},{"name":"message_length_max","type":"int"},{"name":"webfile_dc_id","type":"int"},{"name":"suggested_lang_code","type":"flags.2?string"},{"name":"lang_pack_version","type":"flags.2?int"},{"name":"base_lang_pack_version","type":"flags.2?int"}],"type":"Config"},{"id":"-1910892683","predicate":"nearestDc","params":[{"name":"country","type":"string"},{"name":"this_dc","type":"int"},{"name":"nearest_dc","type":"int"}],"type":"NearestDc"},{"id":"497489295","predicate":"help.appUpdate","params":[{"name":"flags","type":"#"},{"name":"can_not_skip","type":"flags.0?true"},{"name":"id","type":"int"},{"name":"version","type":"string"},{"name":"text","type":"string"},{"name":"entities","type":"Vector<MessageEntity>"},{"name":"document","type":"flags.1?Document"},{"name":"url","type":"flags.2?string"}],"type":"help.AppUpdate"},{"id":"-1000708810","predicate":"help.noAppUpdate","params":[],"type":"help.AppUpdate"},{"id":"415997816","predicate":"help.inviteText","params":[{"name":"message","type":"string"}],"type":"help.InviteText"},{"id":"314359194","predicate":"updateNewEncryptedMessage","params":[{"name":"message","type":"EncryptedMessage"},{"name":"qts","type":"int"}],"type":"Update"},{"id":"386986326","predicate":"updateEncryptedChatTyping","params":[{"name":"chat_id","type":"int"}],"type":"Update"},{"id":"-1264392051","predicate":"updateEncryption","params":[{"name":"chat","type":"EncryptedChat"},{"name":"date","type":"int"}],"type":"Update"},{"id":"956179895","predicate":"updateEncryptedMessagesRead","params":[{"name":"chat_id","type":"int"},{"name":"max_date","type":"int"},{"name":"date","type":"int"}],"type":"Update"},{"id":"-1417756512","predicate":"encryptedChatEmpty","params":[{"name":"id","type":"int"}],"type":"EncryptedChat"},{"id":"1006044124","predicate":"encryptedChatWaiting","params":[{"name":"id","type":"int"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"}],"type":"EncryptedChat"},{"id":"-931638658","predicate":"encryptedChatRequested","params":[{"name":"id","type":"int"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"g_a","type":"bytes"}],"type":"EncryptedChat"},{"id":"-94974410","predicate":"encryptedChat","params":[{"name":"id","type":"int"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"g_a_or_b","type":"bytes"},{"name":"key_fingerprint","type":"long"}],"type":"EncryptedChat"},{"id":"332848423","predicate":"encryptedChatDiscarded","params":[{"name":"id","type":"int"}],"type":"EncryptedChat"},{"id":"-247351839","predicate":"inputEncryptedChat","params":[{"name":"chat_id","type":"int"},{"name":"access_hash","type":"long"}],"type":"InputEncryptedChat"},{"id":"-1038136962","predicate":"encryptedFileEmpty","params":[],"type":"EncryptedFile"},{"id":"1248893260","predicate":"encryptedFile","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"size","type":"int"},{"name":"dc_id","type":"int"},{"name":"key_fingerprint","type":"int"}],"type":"EncryptedFile"},{"id":"406307684","predicate":"inputEncryptedFileEmpty","params":[],"type":"InputEncryptedFile"},{"id":"1690108678","predicate":"inputEncryptedFileUploaded","params":[{"name":"id","type":"long"},{"name":"parts","type":"int"},{"name":"md5_checksum","type":"string"},{"name":"key_fingerprint","type":"int"}],"type":"InputEncryptedFile"},{"id":"1511503333","predicate":"inputEncryptedFile","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputEncryptedFile"},{"id":"-182231723","predicate":"inputEncryptedFileLocation","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputFileLocation"},{"id":"-317144808","predicate":"encryptedMessage","params":[{"name":"random_id","type":"long"},{"name":"chat_id","type":"int"},{"name":"date","type":"int"},{"name":"bytes","type":"bytes"},{"name":"file","type":"EncryptedFile"}],"type":"EncryptedMessage"},{"id":"594758406","predicate":"encryptedMessageService","params":[{"name":"random_id","type":"long"},{"name":"chat_id","type":"int"},{"name":"date","type":"int"},{"name":"bytes","type":"bytes"}],"type":"EncryptedMessage"},{"id":"-1058912715","predicate":"messages.dhConfigNotModified","params":[{"name":"random","type":"bytes"}],"type":"messages.DhConfig"},{"id":"740433629","predicate":"messages.dhConfig","params":[{"name":"g","type":"int"},{"name":"p","type":"bytes"},{"name":"version","type":"int"},{"name":"random","type":"bytes"}],"type":"messages.DhConfig"},{"id":"1443858741","predicate":"messages.sentEncryptedMessage","params":[{"name":"date","type":"int"}],"type":"messages.SentEncryptedMessage"},{"id":"-1802240206","predicate":"messages.sentEncryptedFile","params":[{"name":"date","type":"int"},{"name":"file","type":"EncryptedFile"}],"type":"messages.SentEncryptedMessage"},{"id":"-95482955","predicate":"inputFileBig","params":[{"name":"id","type":"long"},{"name":"parts","type":"int"},{"name":"name","type":"string"}],"type":"InputFile"},{"id":"767652808","predicate":"inputEncryptedFileBigUploaded","params":[{"name":"id","type":"long"},{"name":"parts","type":"int"},{"name":"key_fingerprint","type":"int"}],"type":"InputEncryptedFile"},{"id":"-364179876","predicate":"updateChatParticipantAdd","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"int"},{"name":"inviter_id","type":"int"},{"name":"date","type":"int"},{"name":"version","type":"int"}],"type":"Update"},{"id":"1851755554","predicate":"updateChatParticipantDelete","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"int"},{"name":"version","type":"int"}],"type":"Update"},{"id":"-1906403213","predicate":"updateDcOptions","params":[{"name":"dc_options","type":"Vector<DcOption>"}],"type":"Update"},{"id":"1530447553","predicate":"inputMediaUploadedDocument","params":[{"name":"flags","type":"#"},{"name":"nosound_video","type":"flags.3?true"},{"name":"file","type":"InputFile"},{"name":"thumb","type":"flags.2?InputFile"},{"name":"mime_type","type":"string"},{"name":"attributes","type":"Vector<DocumentAttribute>"},{"name":"stickers","type":"flags.0?Vector<InputDocument>"},{"name":"ttl_seconds","type":"flags.1?int"}],"type":"InputMedia"},{"id":"598418386","predicate":"inputMediaDocument","params":[{"name":"flags","type":"#"},{"name":"id","type":"InputDocument"},{"name":"ttl_seconds","type":"flags.0?int"}],"type":"InputMedia"},{"id":"-1666158377","predicate":"messageMediaDocument","params":[{"name":"flags","type":"#"},{"name":"document","type":"flags.0?Document"},{"name":"ttl_seconds","type":"flags.2?int"}],"type":"MessageMedia"},{"id":"1928391342","predicate":"inputDocumentEmpty","params":[],"type":"InputDocument"},{"id":"448771445","predicate":"inputDocument","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"}],"type":"InputDocument"},{"id":"-1160743548","predicate":"inputDocumentFileLocation","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"},{"name":"thumb_size","type":"string"}],"type":"InputFileLocation"},{"id":"922273905","predicate":"documentEmpty","params":[{"name":"id","type":"long"}],"type":"Document"},{"id":"-1683841855","predicate":"document","params":[{"name":"flags","type":"#"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"},{"name":"date","type":"int"},{"name":"mime_type","type":"string"},{"name":"size","type":"int"},{"name":"thumbs","type":"flags.0?Vector<PhotoSize>"},{"name":"dc_id","type":"int"},{"name":"attributes","type":"Vector<DocumentAttribute>"}],"type":"Document"},{"id":"398898678","predicate":"help.support","params":[{"name":"phone_number","type":"string"},{"name":"user","type":"User"}],"type":"help.Support"},{"id":"-1613493288","predicate":"notifyPeer","params":[{"name":"peer","type":"Peer"}],"type":"NotifyPeer"},{"id":"-1261946036","predicate":"notifyUsers","params":[],"type":"NotifyPeer"},{"id":"-1073230141","predicate":"notifyChats","params":[],"type":"NotifyPeer"},{"id":"-2131957734","predicate":"updateUserBlocked","params":[{"name":"user_id","type":"int"},{"name":"blocked","type":"Bool"}],"type":"Update"},{"id":"-1094555409","predicate":"updateNotifySettings","params":[{"name":"peer","type":"NotifyPeer"},{"name":"notify_settings","type":"PeerNotifySettings"}],"type":"Update"},{"id":"381645902","predicate":"sendMessageTypingAction","params":[],"type":"SendMessageAction"},{"id":"-44119819","predicate":"sendMessageCancelAction","params":[],"type":"SendMessageAction"},{"id":"-1584933265","predicate":"sendMessageRecordVideoAction","params":[],"type":"SendMessageAction"},{"id":"-378127636","predicate":"sendMessageUploadVideoAction","params":[{"name":"progress","type":"int"}],"type":"SendMessageAction"},{"id":"-718310409","predicate":"sendMessageRecordAudioAction","params":[],"type":"SendMessageAction"},{"id":"-212740181","predicate":"sendMessageUploadAudioAction","params":[{"name":"progress","type":"int"}],"type":"SendMessageAction"},{"id":"-774682074","predicate":"sendMessageUploadPhotoAction","params":[{"name":"progress","type":"int"}],"type":"SendMessageAction"},{"id":"-1441998364","predicate":"sendMessageUploadDocumentAction","params":[{"name":"progress","type":"int"}],"type":"SendMessageAction"},{"id":"393186209","predicate":"sendMessageGeoLocationAction","params":[],"type":"SendMessageAction"},{"id":"1653390447","predicate":"sendMessageChooseContactAction","params":[],"type":"SendMessageAction"},{"id":"-1290580579","predicate":"contacts.found","params":[{"name":"my_results","type":"Vector<Peer>"},{"name":"results","type":"Vector<Peer>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.Found"},{"id":"-337352679","predicate":"updateServiceNotification","params":[{"name":"flags","type":"#"},{"name":"popup","type":"flags.0?true"},{"name":"inbox_date","type":"flags.1?int"},{"name":"type","type":"string"},{"name":"message","type":"string"},{"name":"media","type":"MessageMedia"},{"name":"entities","type":"Vector<MessageEntity>"}],"type":"Update"},{"id":"-496024847","predicate":"userStatusRecently","params":[],"type":"UserStatus"},{"id":"129960444","predicate":"userStatusLastWeek","params":[],"type":"UserStatus"},{"id":"2011940674","predicate":"userStatusLastMonth","params":[],"type":"UserStatus"},{"id":"-298113238","predicate":"updatePrivacy","params":[{"name":"key","type":"PrivacyKey"},{"name":"rules","type":"Vector<PrivacyRule>"}],"type":"Update"},{"id":"1335282456","predicate":"inputPrivacyKeyStatusTimestamp","params":[],"type":"InputPrivacyKey"},{"id":"-1137792208","predicate":"privacyKeyStatusTimestamp","params":[],"type":"PrivacyKey"},{"id":"218751099","predicate":"inputPrivacyValueAllowContacts","params":[],"type":"InputPrivacyRule"},{"id":"407582158","predicate":"inputPrivacyValueAllowAll","params":[],"type":"InputPrivacyRule"},{"id":"320652927","predicate":"inputPrivacyValueAllowUsers","params":[{"name":"users","type":"Vector<InputUser>"}],"type":"InputPrivacyRule"},{"id":"195371015","predicate":"inputPrivacyValueDisallowContacts","params":[],"type":"InputPrivacyRule"},{"id":"-697604407","predicate":"inputPrivacyValueDisallowAll","params":[],"type":"InputPrivacyRule"},{"id":"-1877932953","predicate":"inputPrivacyValueDisallowUsers","params":[{"name":"users","type":"Vector<InputUser>"}],"type":"InputPrivacyRule"},{"id":"-123988","predicate":"privacyValueAllowContacts","params":[],"type":"PrivacyRule"},{"id":"1698855810","predicate":"privacyValueAllowAll","params":[],"type":"PrivacyRule"},{"id":"1297858060","predicate":"privacyValueAllowUsers","params":[{"name":"users","type":"Vector<int>"}],"type":"PrivacyRule"},{"id":"-125240806","predicate":"privacyValueDisallowContacts","params":[],"type":"PrivacyRule"},{"id":"-1955338397","predicate":"privacyValueDisallowAll","params":[],"type":"PrivacyRule"},{"id":"209668535","predicate":"privacyValueDisallowUsers","params":[{"name":"users","type":"Vector<int>"}],"type":"PrivacyRule"},{"id":"1352683077","predicate":"account.privacyRules","params":[{"name":"rules","type":"Vector<PrivacyRule>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"account.PrivacyRules"},{"id":"-1194283041","predicate":"accountDaysTTL","params":[{"name":"days","type":"int"}],"type":"AccountDaysTTL"},{"id":"314130811","predicate":"updateUserPhone","params":[{"name":"user_id","type":"int"},{"name":"phone","type":"string"}],"type":"Update"},{"id":"1815593308","predicate":"documentAttributeImageSize","params":[{"name":"w","type":"int"},{"name":"h","type":"int"}],"type":"DocumentAttribute"},{"id":"297109817","predicate":"documentAttributeAnimated","params":[],"type":"DocumentAttribute"},{"id":"1662637586","predicate":"documentAttributeSticker","params":[{"name":"flags","type":"#"},{"name":"mask","type":"flags.1?true"},{"name":"alt","type":"string"},{"name":"stickerset","type":"InputStickerSet"},{"name":"mask_coords","type":"flags.0?MaskCoords"}],"type":"DocumentAttribute"},{"id":"250621158","predicate":"documentAttributeVideo","params":[{"name":"flags","type":"#"},{"name":"round_message","type":"flags.0?true"},{"name":"supports_streaming","type":"flags.1?true"},{"name":"duration","type":"int"},{"name":"w","type":"int"},{"name":"h","type":"int"}],"type":"DocumentAttribute"},{"id":"-1739392570","predicate":"documentAttributeAudio","params":[{"name":"flags","type":"#"},{"name":"voice","type":"flags.10?true"},{"name":"duration","type":"int"},{"name":"title","type":"flags.0?string"},{"name":"performer","type":"flags.1?string"},{"name":"waveform","type":"flags.2?bytes"}],"type":"DocumentAttribute"},{"id":"358154344","predicate":"documentAttributeFilename","params":[{"name":"file_name","type":"string"}],"type":"DocumentAttribute"},{"id":"-244016606","predicate":"messages.stickersNotModified","params":[],"type":"messages.Stickers"},{"id":"-463889475","predicate":"messages.stickers","params":[{"name":"hash","type":"int"},{"name":"stickers","type":"Vector<Document>"}],"type":"messages.Stickers"},{"id":"313694676","predicate":"stickerPack","params":[{"name":"emoticon","type":"string"},{"name":"documents","type":"Vector<long>"}],"type":"StickerPack"},{"id":"-395967805","predicate":"messages.allStickersNotModified","params":[],"type":"messages.AllStickers"},{"id":"-302170017","predicate":"messages.allStickers","params":[{"name":"hash","type":"int"},{"name":"sets","type":"Vector<StickerSet>"}],"type":"messages.AllStickers"},{"id":"-1667805217","predicate":"updateReadHistoryInbox","params":[{"name":"flags","type":"#"},{"name":"folder_id","type":"flags.0?int"},{"name":"peer","type":"Peer"},{"name":"max_id","type":"int"},{"name":"still_unread_count","type":"int"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"791617983","predicate":"updateReadHistoryOutbox","params":[{"name":"peer","type":"Peer"},{"name":"max_id","type":"int"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-2066640507","predicate":"messages.affectedMessages","params":[{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"messages.AffectedMessages"},{"id":"2139689491","predicate":"updateWebPage","params":[{"name":"webpage","type":"WebPage"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-350980120","predicate":"webPageEmpty","params":[{"name":"id","type":"long"}],"type":"WebPage"},{"id":"-981018084","predicate":"webPagePending","params":[{"name":"id","type":"long"},{"name":"date","type":"int"}],"type":"WebPage"},{"id":"-94051982","predicate":"webPage","params":[{"name":"flags","type":"#"},{"name":"id","type":"long"},{"name":"url","type":"string"},{"name":"display_url","type":"string"},{"name":"hash","type":"int"},{"name":"type","type":"flags.0?string"},{"name":"site_name","type":"flags.1?string"},{"name":"title","type":"flags.2?string"},{"name":"description","type":"flags.3?string"},{"name":"photo","type":"flags.4?Photo"},{"name":"embed_url","type":"flags.5?string"},{"name":"embed_type","type":"flags.5?string"},{"name":"embed_width","type":"flags.6?int"},{"name":"embed_height","type":"flags.6?int"},{"name":"duration","type":"flags.7?int"},{"name":"author","type":"flags.8?string"},{"name":"document","type":"flags.9?Document"},{"name":"documents","type":"flags.11?Vector<Document>"},{"name":"cached_page","type":"flags.10?Page"}],"type":"WebPage"},{"id":"-1557277184","predicate":"messageMediaWebPage","params":[{"name":"webpage","type":"WebPage"}],"type":"MessageMedia"},{"id":"-1392388579","predicate":"authorization","params":[{"name":"flags","type":"#"},{"name":"current","type":"flags.0?true"},{"name":"official_app","type":"flags.1?true"},{"name":"password_pending","type":"flags.2?true"},{"name":"hash","type":"long"},{"name":"device_model","type":"string"},{"name":"platform","type":"string"},{"name":"system_version","type":"string"},{"name":"api_id","type":"int"},{"name":"app_name","type":"string"},{"name":"app_version","type":"string"},{"name":"date_created","type":"int"},{"name":"date_active","type":"int"},{"name":"ip","type":"string"},{"name":"country","type":"string"},{"name":"region","type":"string"}],"type":"Authorization"},{"id":"307276766","predicate":"account.authorizations","params":[{"name":"authorizations","type":"Vector<Authorization>"}],"type":"account.Authorizations"},{"id":"-1390001672","predicate":"account.password","params":[{"name":"flags","type":"#"},{"name":"has_recovery","type":"flags.0?true"},{"name":"has_secure_values","type":"flags.1?true"},{"name":"has_password","type":"flags.2?true"},{"name":"current_algo","type":"flags.2?PasswordKdfAlgo"},{"name":"srp_B","type":"flags.2?bytes"},{"name":"srp_id","type":"flags.2?long"},{"name":"hint","type":"flags.3?string"},{"name":"email_unconfirmed_pattern","type":"flags.4?string"},{"name":"new_algo","type":"PasswordKdfAlgo"},{"name":"new_secure_algo","type":"SecurePasswordKdfAlgo"},{"name":"secure_random","type":"bytes"}],"type":"account.Password"},{"id":"-1705233435","predicate":"account.passwordSettings","params":[{"name":"flags","type":"#"},{"name":"email","type":"flags.0?string"},{"name":"secure_settings","type":"flags.1?SecureSecretSettings"}],"type":"account.PasswordSettings"},{"id":"-1036572727","predicate":"account.passwordInputSettings","params":[{"name":"flags","type":"#"},{"name":"new_algo","type":"flags.0?PasswordKdfAlgo"},{"name":"new_password_hash","type":"flags.0?bytes"},{"name":"hint","type":"flags.0?string"},{"name":"email","type":"flags.1?string"},{"name":"new_secure_settings","type":"flags.2?SecureSecretSettings"}],"type":"account.PasswordInputSettings"},{"id":"326715557","predicate":"auth.passwordRecovery","params":[{"name":"email_pattern","type":"string"}],"type":"auth.PasswordRecovery"},{"id":"-1052959727","predicate":"inputMediaVenue","params":[{"name":"geo_point","type":"InputGeoPoint"},{"name":"title","type":"string"},{"name":"address","type":"string"},{"name":"provider","type":"string"},{"name":"venue_id","type":"string"},{"name":"venue_type","type":"string"}],"type":"InputMedia"},{"id":"784356159","predicate":"messageMediaVenue","params":[{"name":"geo","type":"GeoPoint"},{"name":"title","type":"string"},{"name":"address","type":"string"},{"name":"provider","type":"string"},{"name":"venue_id","type":"string"},{"name":"venue_type","type":"string"}],"type":"MessageMedia"},{"id":"-1551583367","predicate":"receivedNotifyMessage","params":[{"name":"id","type":"int"},{"name":"flags","type":"int"}],"type":"ReceivedNotifyMessage"},{"id":"1776236393","predicate":"chatInviteEmpty","params":[],"type":"ExportedChatInvite"},{"id":"-64092740","predicate":"chatInviteExported","params":[{"name":"link","type":"string"}],"type":"ExportedChatInvite"},{"id":"1516793212","predicate":"chatInviteAlready","params":[{"name":"chat","type":"Chat"}],"type":"ChatInvite"},{"id":"-540871282","predicate":"chatInvite","params":[{"name":"flags","type":"#"},{"name":"channel","type":"flags.0?true"},{"name":"broadcast","type":"flags.1?true"},{"name":"public","type":"flags.2?true"},{"name":"megagroup","type":"flags.3?true"},{"name":"title","type":"string"},{"name":"photo","type":"Photo"},{"name":"participants_count","type":"int"},{"name":"participants","type":"flags.4?Vector<User>"}],"type":"ChatInvite"},{"id":"-123931160","predicate":"messageActionChatJoinedByLink","params":[{"name":"inviter_id","type":"int"}],"type":"MessageAction"},{"id":"1757493555","predicate":"updateReadMessagesContents","params":[{"name":"messages","type":"Vector<int>"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-4838507","predicate":"inputStickerSetEmpty","params":[],"type":"InputStickerSet"},{"id":"-1645763991","predicate":"inputStickerSetID","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputStickerSet"},{"id":"-2044933984","predicate":"inputStickerSetShortName","params":[{"name":"short_name","type":"string"}],"type":"InputStickerSet"},{"id":"-290164953","predicate":"stickerSet","params":[{"name":"flags","type":"#"},{"name":"archived","type":"flags.1?true"},{"name":"official","type":"flags.2?true"},{"name":"masks","type":"flags.3?true"},{"name":"animated","type":"flags.5?true"},{"name":"installed_date","type":"flags.0?int"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"title","type":"string"},{"name":"short_name","type":"string"},{"name":"thumb","type":"flags.4?PhotoSize"},{"name":"thumb_dc_id","type":"flags.4?int"},{"name":"count","type":"int"},{"name":"hash","type":"int"}],"type":"StickerSet"},{"id":"-1240849242","predicate":"messages.stickerSet","params":[{"name":"set","type":"StickerSet"},{"name":"packs","type":"Vector<StickerPack>"},{"name":"documents","type":"Vector<Document>"}],"type":"messages.StickerSet"},{"id":"-1820043071","predicate":"user","params":[{"name":"flags","type":"#"},{"name":"self","type":"flags.10?true"},{"name":"contact","type":"flags.11?true"},{"name":"mutual_contact","type":"flags.12?true"},{"name":"deleted","type":"flags.13?true"},{"name":"bot","type":"flags.14?true"},{"name":"bot_chat_history","type":"flags.15?true"},{"name":"bot_nochats","type":"flags.16?true"},{"name":"verified","type":"flags.17?true"},{"name":"restricted","type":"flags.18?true"},{"name":"min","type":"flags.20?true"},{"name":"bot_inline_geo","type":"flags.21?true"},{"name":"support","type":"flags.23?true"},{"name":"scam","type":"flags.24?true"},{"name":"id","type":"int"},{"name":"access_hash","type":"flags.0?long"},{"name":"first_name","type":"flags.1?string"},{"name":"last_name","type":"flags.2?string"},{"name":"username","type":"flags.3?string"},{"name":"phone","type":"flags.4?string"},{"name":"photo","type":"flags.5?UserProfilePhoto"},{"name":"status","type":"flags.6?UserStatus"},{"name":"bot_info_version","type":"flags.14?int"},{"name":"restriction_reason","type":"flags.18?Vector<RestrictionReason>"},{"name":"bot_inline_placeholder","type":"flags.19?string"},{"name":"lang_code","type":"flags.22?string"}],"type":"User"},{"id":"-1032140601","predicate":"botCommand","params":[{"name":"command","type":"string"},{"name":"description","type":"string"}],"type":"BotCommand"},{"id":"-1729618630","predicate":"botInfo","params":[{"name":"user_id","type":"int"},{"name":"description","type":"string"},{"name":"commands","type":"Vector<BotCommand>"}],"type":"BotInfo"},{"id":"-1560655744","predicate":"keyboardButton","params":[{"name":"text","type":"string"}],"type":"KeyboardButton"},{"id":"2002815875","predicate":"keyboardButtonRow","params":[{"name":"buttons","type":"Vector<KeyboardButton>"}],"type":"KeyboardButtonRow"},{"id":"-1606526075","predicate":"replyKeyboardHide","params":[{"name":"flags","type":"#"},{"name":"selective","type":"flags.2?true"}],"type":"ReplyMarkup"},{"id":"-200242528","predicate":"replyKeyboardForceReply","params":[{"name":"flags","type":"#"},{"name":"single_use","type":"flags.1?true"},{"name":"selective","type":"flags.2?true"}],"type":"ReplyMarkup"},{"id":"889353612","predicate":"replyKeyboardMarkup","params":[{"name":"flags","type":"#"},{"name":"resize","type":"flags.0?true"},{"name":"single_use","type":"flags.1?true"},{"name":"selective","type":"flags.2?true"},{"name":"rows","type":"Vector<KeyboardButtonRow>"}],"type":"ReplyMarkup"},{"id":"2072935910","predicate":"inputPeerUser","params":[{"name":"user_id","type":"int"},{"name":"access_hash","type":"long"}],"type":"InputPeer"},{"id":"-668391402","predicate":"inputUser","params":[{"name":"user_id","type":"int"},{"name":"access_hash","type":"long"}],"type":"InputUser"},{"id":"-1148011883","predicate":"messageEntityUnknown","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"-100378723","predicate":"messageEntityMention","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1868782349","predicate":"messageEntityHashtag","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1827637959","predicate":"messageEntityBotCommand","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1859134776","predicate":"messageEntityUrl","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1692693954","predicate":"messageEntityEmail","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"-1117713463","predicate":"messageEntityBold","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"-2106619040","predicate":"messageEntityItalic","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"681706865","predicate":"messageEntityCode","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1938967520","predicate":"messageEntityPre","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"},{"name":"language","type":"string"}],"type":"MessageEntity"},{"id":"1990644519","predicate":"messageEntityTextUrl","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"},{"name":"url","type":"string"}],"type":"MessageEntity"},{"id":"301019932","predicate":"updateShortSentMessage","params":[{"name":"flags","type":"#"},{"name":"out","type":"flags.1?true"},{"name":"id","type":"int"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"},{"name":"date","type":"int"},{"name":"media","type":"flags.9?MessageMedia"},{"name":"entities","type":"flags.7?Vector<MessageEntity>"}],"type":"Updates"},{"id":"-292807034","predicate":"inputChannelEmpty","params":[],"type":"InputChannel"},{"id":"-1343524562","predicate":"inputChannel","params":[{"name":"channel_id","type":"int"},{"name":"access_hash","type":"long"}],"type":"InputChannel"},{"id":"-1109531342","predicate":"peerChannel","params":[{"name":"channel_id","type":"int"}],"type":"Peer"},{"id":"548253432","predicate":"inputPeerChannel","params":[{"name":"channel_id","type":"int"},{"name":"access_hash","type":"long"}],"type":"InputPeer"},{"id":"-753232354","predicate":"channel","params":[{"name":"flags","type":"#"},{"name":"creator","type":"flags.0?true"},{"name":"left","type":"flags.2?true"},{"name":"broadcast","type":"flags.5?true"},{"name":"verified","type":"flags.7?true"},{"name":"megagroup","type":"flags.8?true"},{"name":"restricted","type":"flags.9?true"},{"name":"signatures","type":"flags.11?true"},{"name":"min","type":"flags.12?true"},{"name":"scam","type":"flags.19?true"},{"name":"has_link","type":"flags.20?true"},{"name":"has_geo","type":"flags.21?true"},{"name":"slowmode_enabled","type":"flags.22?true"},{"name":"id","type":"int"},{"name":"access_hash","type":"flags.13?long"},{"name":"title","type":"string"},{"name":"username","type":"flags.6?string"},{"name":"photo","type":"ChatPhoto"},{"name":"date","type":"int"},{"name":"version","type":"int"},{"name":"restriction_reason","type":"flags.9?Vector<RestrictionReason>"},{"name":"admin_rights","type":"flags.14?ChatAdminRights"},{"name":"banned_rights","type":"flags.15?ChatBannedRights"},{"name":"default_banned_rights","type":"flags.18?ChatBannedRights"},{"name":"participants_count","type":"flags.17?int"}],"type":"Chat"},{"id":"681420594","predicate":"channelForbidden","params":[{"name":"flags","type":"#"},{"name":"broadcast","type":"flags.5?true"},{"name":"megagroup","type":"flags.8?true"},{"name":"id","type":"int"},{"name":"access_hash","type":"long"},{"name":"title","type":"string"},{"name":"until_date","type":"flags.16?int"}],"type":"Chat"},{"id":"2131196633","predicate":"contacts.resolvedPeer","params":[{"name":"peer","type":"Peer"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.ResolvedPeer"},{"id":"763976820","predicate":"channelFull","params":[{"name":"flags","type":"#"},{"name":"can_view_participants","type":"flags.3?true"},{"name":"can_set_username","type":"flags.6?true"},{"name":"can_set_stickers","type":"flags.7?true"},{"name":"hidden_prehistory","type":"flags.10?true"},{"name":"can_view_stats","type":"flags.12?true"},{"name":"can_set_location","type":"flags.16?true"},{"name":"has_scheduled","type":"flags.19?true"},{"name":"id","type":"int"},{"name":"about","type":"string"},{"name":"participants_count","type":"flags.0?int"},{"name":"admins_count","type":"flags.1?int"},{"name":"kicked_count","type":"flags.2?int"},{"name":"banned_count","type":"flags.2?int"},{"name":"online_count","type":"flags.13?int"},{"name":"read_inbox_max_id","type":"int"},{"name":"read_outbox_max_id","type":"int"},{"name":"unread_count","type":"int"},{"name":"chat_photo","type":"Photo"},{"name":"notify_settings","type":"PeerNotifySettings"},{"name":"exported_invite","type":"ExportedChatInvite"},{"name":"bot_info","type":"Vector<BotInfo>"},{"name":"migrated_from_chat_id","type":"flags.4?int"},{"name":"migrated_from_max_id","type":"flags.4?int"},{"name":"pinned_msg_id","type":"flags.5?int"},{"name":"stickerset","type":"flags.8?StickerSet"},{"name":"available_min_id","type":"flags.9?int"},{"name":"folder_id","type":"flags.11?int"},{"name":"linked_chat_id","type":"flags.14?int"},{"name":"location","type":"flags.15?ChannelLocation"},{"name":"slowmode_seconds","type":"flags.17?int"},{"name":"slowmode_next_send_date","type":"flags.18?int"},{"name":"pts","type":"int"}],"type":"ChatFull"},{"id":"182649427","predicate":"messageRange","params":[{"name":"min_id","type":"int"},{"name":"max_id","type":"int"}],"type":"MessageRange"},{"id":"-1725551049","predicate":"messages.channelMessages","params":[{"name":"flags","type":"#"},{"name":"inexact","type":"flags.1?true"},{"name":"pts","type":"int"},{"name":"count","type":"int"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"messages.Messages"},{"id":"-1781355374","predicate":"messageActionChannelCreate","params":[{"name":"title","type":"string"}],"type":"MessageAction"},{"id":"-352032773","predicate":"updateChannelTooLong","params":[{"name":"flags","type":"#"},{"name":"channel_id","type":"int"},{"name":"pts","type":"flags.0?int"}],"type":"Update"},{"id":"-1227598250","predicate":"updateChannel","params":[{"name":"channel_id","type":"int"}],"type":"Update"},{"id":"1656358105","predicate":"updateNewChannelMessage","params":[{"name":"message","type":"Message"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"856380452","predicate":"updateReadChannelInbox","params":[{"name":"flags","type":"#"},{"name":"folder_id","type":"flags.0?int"},{"name":"channel_id","type":"int"},{"name":"max_id","type":"int"},{"name":"still_unread_count","type":"int"},{"name":"pts","type":"int"}],"type":"Update"},{"id":"-1015733815","predicate":"updateDeleteChannelMessages","params":[{"name":"channel_id","type":"int"},{"name":"messages","type":"Vector<int>"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-1734268085","predicate":"updateChannelMessageViews","params":[{"name":"channel_id","type":"int"},{"name":"id","type":"int"},{"name":"views","type":"int"}],"type":"Update"},{"id":"1041346555","predicate":"updates.channelDifferenceEmpty","params":[{"name":"flags","type":"#"},{"name":"final","type":"flags.0?true"},{"name":"pts","type":"int"},{"name":"timeout","type":"flags.1?int"}],"type":"updates.ChannelDifference"},{"id":"-1531132162","predicate":"updates.channelDifferenceTooLong","params":[{"name":"flags","type":"#"},{"name":"final","type":"flags.0?true"},{"name":"timeout","type":"flags.1?int"},{"name":"dialog","type":"Dialog"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"updates.ChannelDifference"},{"id":"543450958","predicate":"updates.channelDifference","params":[{"name":"flags","type":"#"},{"name":"final","type":"flags.0?true"},{"name":"pts","type":"int"},{"name":"timeout","type":"flags.1?int"},{"name":"new_messages","type":"Vector<Message>"},{"name":"other_updates","type":"Vector<Update>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"updates.ChannelDifference"},{"id":"-1798033689","predicate":"channelMessagesFilterEmpty","params":[],"type":"ChannelMessagesFilter"},{"id":"-847783593","predicate":"channelMessagesFilter","params":[{"name":"flags","type":"#"},{"name":"exclude_new_messages","type":"flags.1?true"},{"name":"ranges","type":"Vector<MessageRange>"}],"type":"ChannelMessagesFilter"},{"id":"367766557","predicate":"channelParticipant","params":[{"name":"user_id","type":"int"},{"name":"date","type":"int"}],"type":"ChannelParticipant"},{"id":"-1557620115","predicate":"channelParticipantSelf","params":[{"name":"user_id","type":"int"},{"name":"inviter_id","type":"int"},{"name":"date","type":"int"}],"type":"ChannelParticipant"},{"id":"-2138237532","predicate":"channelParticipantCreator","params":[{"name":"flags","type":"#"},{"name":"user_id","type":"int"},{"name":"rank","type":"flags.0?string"}],"type":"ChannelParticipant"},{"id":"-566281095","predicate":"channelParticipantsRecent","params":[],"type":"ChannelParticipantsFilter"},{"id":"-1268741783","predicate":"channelParticipantsAdmins","params":[],"type":"ChannelParticipantsFilter"},{"id":"-1548400251","predicate":"channelParticipantsKicked","params":[{"name":"q","type":"string"}],"type":"ChannelParticipantsFilter"},{"id":"-177282392","predicate":"channels.channelParticipants","params":[{"name":"count","type":"int"},{"name":"participants","type":"Vector<ChannelParticipant>"},{"name":"users","type":"Vector<User>"}],"type":"channels.ChannelParticipants"},{"id":"-791039645","predicate":"channels.channelParticipant","params":[{"name":"participant","type":"ChannelParticipant"},{"name":"users","type":"Vector<User>"}],"type":"channels.ChannelParticipant"},{"id":"-636267638","predicate":"chatParticipantCreator","params":[{"name":"user_id","type":"int"}],"type":"ChatParticipant"},{"id":"-489233354","predicate":"chatParticipantAdmin","params":[{"name":"user_id","type":"int"},{"name":"inviter_id","type":"int"},{"name":"date","type":"int"}],"type":"ChatParticipant"},{"id":"-1232070311","predicate":"updateChatParticipantAdmin","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"int"},{"name":"is_admin","type":"Bool"},{"name":"version","type":"int"}],"type":"Update"},{"id":"1371385889","predicate":"messageActionChatMigrateTo","params":[{"name":"channel_id","type":"int"}],"type":"MessageAction"},{"id":"-1336546578","predicate":"messageActionChannelMigrateFrom","params":[{"name":"title","type":"string"},{"name":"chat_id","type":"int"}],"type":"MessageAction"},{"id":"-1328445861","predicate":"channelParticipantsBots","params":[],"type":"ChannelParticipantsFilter"},{"id":"2013922064","predicate":"help.termsOfService","params":[{"name":"flags","type":"#"},{"name":"popup","type":"flags.0?true"},{"name":"id","type":"DataJSON"},{"name":"text","type":"string"},{"name":"entities","type":"Vector<MessageEntity>"},{"name":"min_age_confirm","type":"flags.1?int"}],"type":"help.TermsOfService"},{"id":"1753886890","predicate":"updateNewStickerSet","params":[{"name":"stickerset","type":"messages.StickerSet"}],"type":"Update"},{"id":"196268545","predicate":"updateStickerSetsOrder","params":[{"name":"flags","type":"#"},{"name":"masks","type":"flags.0?true"},{"name":"order","type":"Vector<long>"}],"type":"Update"},{"id":"1135492588","predicate":"updateStickerSets","params":[],"type":"Update"},{"id":"372165663","predicate":"foundGif","params":[{"name":"url","type":"string"},{"name":"thumb_url","type":"string"},{"name":"content_url","type":"string"},{"name":"content_type","type":"string"},{"name":"w","type":"int"},{"name":"h","type":"int"}],"type":"FoundGif"},{"id":"-1670052855","predicate":"foundGifCached","params":[{"name":"url","type":"string"},{"name":"photo","type":"Photo"},{"name":"document","type":"Document"}],"type":"FoundGif"},{"id":"1212395773","predicate":"inputMediaGifExternal","params":[{"name":"url","type":"string"},{"name":"q","type":"string"}],"type":"InputMedia"},{"id":"1158290442","predicate":"messages.foundGifs","params":[{"name":"next_offset","type":"int"},{"name":"results","type":"Vector<FoundGif>"}],"type":"messages.FoundGifs"},{"id":"-402498398","predicate":"messages.savedGifsNotModified","params":[],"type":"messages.SavedGifs"},{"id":"772213157","predicate":"messages.savedGifs","params":[{"name":"hash","type":"int"},{"name":"gifs","type":"Vector<Document>"}],"type":"messages.SavedGifs"},{"id":"-1821035490","predicate":"updateSavedGifs","params":[],"type":"Update"},{"id":"864077702","predicate":"inputBotInlineMessageMediaAuto","params":[{"name":"flags","type":"#"},{"name":"message","type":"string"},{"name":"entities","type":"flags.1?Vector<MessageEntity>"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"1036876423","predicate":"inputBotInlineMessageText","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.0?true"},{"name":"message","type":"string"},{"name":"entities","type":"flags.1?Vector<MessageEntity>"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"-2000710887","predicate":"inputBotInlineResult","params":[{"name":"flags","type":"#"},{"name":"id","type":"string"},{"name":"type","type":"string"},{"name":"title","type":"flags.1?string"},{"name":"description","type":"flags.2?string"},{"name":"url","type":"flags.3?string"},{"name":"thumb","type":"flags.4?InputWebDocument"},{"name":"content","type":"flags.5?InputWebDocument"},{"name":"send_message","type":"InputBotInlineMessage"}],"type":"InputBotInlineResult"},{"id":"1984755728","predicate":"botInlineMessageMediaAuto","params":[{"name":"flags","type":"#"},{"name":"message","type":"string"},{"name":"entities","type":"flags.1?Vector<MessageEntity>"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"BotInlineMessage"},{"id":"-1937807902","predicate":"botInlineMessageText","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.0?true"},{"name":"message","type":"string"},{"name":"entities","type":"flags.1?Vector<MessageEntity>"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"BotInlineMessage"},{"id":"295067450","predicate":"botInlineResult","params":[{"name":"flags","type":"#"},{"name":"id","type":"string"},{"name":"type","type":"string"},{"name":"title","type":"flags.1?string"},{"name":"description","type":"flags.2?string"},{"name":"url","type":"flags.3?string"},{"name":"thumb","type":"flags.4?WebDocument"},{"name":"content","type":"flags.5?WebDocument"},{"name":"send_message","type":"BotInlineMessage"}],"type":"BotInlineResult"},{"id":"-1803769784","predicate":"messages.botResults","params":[{"name":"flags","type":"#"},{"name":"gallery","type":"flags.0?true"},{"name":"query_id","type":"long"},{"name":"next_offset","type":"flags.1?string"},{"name":"switch_pm","type":"flags.2?InlineBotSwitchPM"},{"name":"results","type":"Vector<BotInlineResult>"},{"name":"cache_time","type":"int"},{"name":"users","type":"Vector<User>"}],"type":"messages.BotResults"},{"id":"1417832080","predicate":"updateBotInlineQuery","params":[{"name":"flags","type":"#"},{"name":"query_id","type":"long"},{"name":"user_id","type":"int"},{"name":"query","type":"string"},{"name":"geo","type":"flags.0?GeoPoint"},{"name":"offset","type":"string"}],"type":"Update"},{"id":"239663460","predicate":"updateBotInlineSend","params":[{"name":"flags","type":"#"},{"name":"user_id","type":"int"},{"name":"query","type":"string"},{"name":"geo","type":"flags.0?GeoPoint"},{"name":"id","type":"string"},{"name":"msg_id","type":"flags.1?InputBotInlineMessageID"}],"type":"Update"},{"id":"1358283666","predicate":"inputMessagesFilterVoice","params":[],"type":"MessagesFilter"},{"id":"928101534","predicate":"inputMessagesFilterMusic","params":[],"type":"MessagesFilter"},{"id":"-1107622874","predicate":"inputPrivacyKeyChatInvite","params":[],"type":"InputPrivacyKey"},{"id":"1343122938","predicate":"privacyKeyChatInvite","params":[],"type":"PrivacyKey"},{"id":"1571494644","predicate":"exportedMessageLink","params":[{"name":"link","type":"string"},{"name":"html","type":"string"}],"type":"ExportedMessageLink"},{"id":"-332168592","predicate":"messageFwdHeader","params":[{"name":"flags","type":"#"},{"name":"from_id","type":"flags.0?int"},{"name":"from_name","type":"flags.5?string"},{"name":"date","type":"int"},{"name":"channel_id","type":"flags.1?int"},{"name":"channel_post","type":"flags.2?int"},{"name":"post_author","type":"flags.3?string"},{"name":"saved_from_peer","type":"flags.4?Peer"},{"name":"saved_from_msg_id","type":"flags.4?int"}],"type":"MessageFwdHeader"},{"id":"457133559","predicate":"updateEditChannelMessage","params":[{"name":"message","type":"Message"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-1738988427","predicate":"updateChannelPinnedMessage","params":[{"name":"channel_id","type":"int"},{"name":"id","type":"int"}],"type":"Update"},{"id":"-1799538451","predicate":"messageActionPinMessage","params":[],"type":"MessageAction"},{"id":"1923290508","predicate":"auth.codeTypeSms","params":[],"type":"auth.CodeType"},{"id":"1948046307","predicate":"auth.codeTypeCall","params":[],"type":"auth.CodeType"},{"id":"577556219","predicate":"auth.codeTypeFlashCall","params":[],"type":"auth.CodeType"},{"id":"1035688326","predicate":"auth.sentCodeTypeApp","params":[{"name":"length","type":"int"}],"type":"auth.SentCodeType"},{"id":"-1073693790","predicate":"auth.sentCodeTypeSms","params":[{"name":"length","type":"int"}],"type":"auth.SentCodeType"},{"id":"1398007207","predicate":"auth.sentCodeTypeCall","params":[{"name":"length","type":"int"}],"type":"auth.SentCodeType"},{"id":"-1425815847","predicate":"auth.sentCodeTypeFlashCall","params":[{"name":"pattern","type":"string"}],"type":"auth.SentCodeType"},{"id":"629866245","predicate":"keyboardButtonUrl","params":[{"name":"text","type":"string"},{"name":"url","type":"string"}],"type":"KeyboardButton"},{"id":"1748655686","predicate":"keyboardButtonCallback","params":[{"name":"text","type":"string"},{"name":"data","type":"bytes"}],"type":"KeyboardButton"},{"id":"-1318425559","predicate":"keyboardButtonRequestPhone","params":[{"name":"text","type":"string"}],"type":"KeyboardButton"},{"id":"-59151553","predicate":"keyboardButtonRequestGeoLocation","params":[{"name":"text","type":"string"}],"type":"KeyboardButton"},{"id":"90744648","predicate":"keyboardButtonSwitchInline","params":[{"name":"flags","type":"#"},{"name":"same_peer","type":"flags.0?true"},{"name":"text","type":"string"},{"name":"query","type":"string"}],"type":"KeyboardButton"},{"id":"1218642516","predicate":"replyInlineMarkup","params":[{"name":"rows","type":"Vector<KeyboardButtonRow>"}],"type":"ReplyMarkup"},{"id":"911761060","predicate":"messages.botCallbackAnswer","params":[{"name":"flags","type":"#"},{"name":"alert","type":"flags.1?true"},{"name":"has_url","type":"flags.3?true"},{"name":"native_ui","type":"flags.4?true"},{"name":"message","type":"flags.0?string"},{"name":"url","type":"flags.2?string"},{"name":"cache_time","type":"int"}],"type":"messages.BotCallbackAnswer"},{"id":"-415938591","predicate":"updateBotCallbackQuery","params":[{"name":"flags","type":"#"},{"name":"query_id","type":"long"},{"name":"user_id","type":"int"},{"name":"peer","type":"Peer"},{"name":"msg_id","type":"int"},{"name":"chat_instance","type":"long"},{"name":"data","type":"flags.0?bytes"},{"name":"game_short_name","type":"flags.1?string"}],"type":"Update"},{"id":"649453030","predicate":"messages.messageEditData","params":[{"name":"flags","type":"#"},{"name":"caption","type":"flags.0?true"}],"type":"messages.MessageEditData"},{"id":"-469536605","predicate":"updateEditMessage","params":[{"name":"message","type":"Message"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-1045340827","predicate":"inputBotInlineMessageMediaGeo","params":[{"name":"flags","type":"#"},{"name":"geo_point","type":"InputGeoPoint"},{"name":"period","type":"int"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"1098628881","predicate":"inputBotInlineMessageMediaVenue","params":[{"name":"flags","type":"#"},{"name":"geo_point","type":"InputGeoPoint"},{"name":"title","type":"string"},{"name":"address","type":"string"},{"name":"provider","type":"string"},{"name":"venue_id","type":"string"},{"name":"venue_type","type":"string"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"-1494368259","predicate":"inputBotInlineMessageMediaContact","params":[{"name":"flags","type":"#"},{"name":"phone_number","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"vcard","type":"string"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"-1222451611","predicate":"botInlineMessageMediaGeo","params":[{"name":"flags","type":"#"},{"name":"geo","type":"GeoPoint"},{"name":"period","type":"int"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"BotInlineMessage"},{"id":"-1970903652","predicate":"botInlineMessageMediaVenue","params":[{"name":"flags","type":"#"},{"name":"geo","type":"GeoPoint"},{"name":"title","type":"string"},{"name":"address","type":"string"},{"name":"provider","type":"string"},{"name":"venue_id","type":"string"},{"name":"venue_type","type":"string"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"BotInlineMessage"},{"id":"416402882","predicate":"botInlineMessageMediaContact","params":[{"name":"flags","type":"#"},{"name":"phone_number","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"vcard","type":"string"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"BotInlineMessage"},{"id":"-1462213465","predicate":"inputBotInlineResultPhoto","params":[{"name":"id","type":"string"},{"name":"type","type":"string"},{"name":"photo","type":"InputPhoto"},{"name":"send_message","type":"InputBotInlineMessage"}],"type":"InputBotInlineResult"},{"id":"-459324","predicate":"inputBotInlineResultDocument","params":[{"name":"flags","type":"#"},{"name":"id","type":"string"},{"name":"type","type":"string"},{"name":"title","type":"flags.1?string"},{"name":"description","type":"flags.2?string"},{"name":"document","type":"InputDocument"},{"name":"send_message","type":"InputBotInlineMessage"}],"type":"InputBotInlineResult"},{"id":"400266251","predicate":"botInlineMediaResult","params":[{"name":"flags","type":"#"},{"name":"id","type":"string"},{"name":"type","type":"string"},{"name":"photo","type":"flags.0?Photo"},{"name":"document","type":"flags.1?Document"},{"name":"title","type":"flags.2?string"},{"name":"description","type":"flags.3?string"},{"name":"send_message","type":"BotInlineMessage"}],"type":"BotInlineResult"},{"id":"-1995686519","predicate":"inputBotInlineMessageID","params":[{"name":"dc_id","type":"int"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputBotInlineMessageID"},{"id":"-103646630","predicate":"updateInlineBotCallbackQuery","params":[{"name":"flags","type":"#"},{"name":"query_id","type":"long"},{"name":"user_id","type":"int"},{"name":"msg_id","type":"InputBotInlineMessageID"},{"name":"chat_instance","type":"long"},{"name":"data","type":"flags.0?bytes"},{"name":"game_short_name","type":"flags.1?string"}],"type":"Update"},{"id":"1008755359","predicate":"inlineBotSwitchPM","params":[{"name":"text","type":"string"},{"name":"start_param","type":"string"}],"type":"InlineBotSwitchPM"},{"id":"863093588","predicate":"messages.peerDialogs","params":[{"name":"dialogs","type":"Vector<Dialog>"},{"name":"messages","type":"Vector<Message>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"},{"name":"state","type":"updates.State"}],"type":"messages.PeerDialogs"},{"id":"-305282981","predicate":"topPeer","params":[{"name":"peer","type":"Peer"},{"name":"rating","type":"double"}],"type":"TopPeer"},{"id":"-1419371685","predicate":"topPeerCategoryBotsPM","params":[],"type":"TopPeerCategory"},{"id":"344356834","predicate":"topPeerCategoryBotsInline","params":[],"type":"TopPeerCategory"},{"id":"104314861","predicate":"topPeerCategoryCorrespondents","params":[],"type":"TopPeerCategory"},{"id":"-1122524854","predicate":"topPeerCategoryGroups","params":[],"type":"TopPeerCategory"},{"id":"371037736","predicate":"topPeerCategoryChannels","params":[],"type":"TopPeerCategory"},{"id":"-75283823","predicate":"topPeerCategoryPeers","params":[{"name":"category","type":"TopPeerCategory"},{"name":"count","type":"int"},{"name":"peers","type":"Vector<TopPeer>"}],"type":"TopPeerCategoryPeers"},{"id":"-567906571","predicate":"contacts.topPeersNotModified","params":[],"type":"contacts.TopPeers"},{"id":"1891070632","predicate":"contacts.topPeers","params":[{"name":"categories","type":"Vector<TopPeerCategoryPeers>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"contacts.TopPeers"},{"id":"892193368","predicate":"messageEntityMentionName","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"},{"name":"user_id","type":"int"}],"type":"MessageEntity"},{"id":"546203849","predicate":"inputMessageEntityMentionName","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"},{"name":"user_id","type":"InputUser"}],"type":"MessageEntity"},{"id":"975236280","predicate":"inputMessagesFilterChatPhotos","params":[],"type":"MessagesFilter"},{"id":"634833351","predicate":"updateReadChannelOutbox","params":[{"name":"channel_id","type":"int"},{"name":"max_id","type":"int"}],"type":"Update"},{"id":"-299124375","predicate":"updateDraftMessage","params":[{"name":"peer","type":"Peer"},{"name":"draft","type":"DraftMessage"}],"type":"Update"},{"id":"453805082","predicate":"draftMessageEmpty","params":[{"name":"flags","type":"#"},{"name":"date","type":"flags.0?int"}],"type":"DraftMessage"},{"id":"-40996577","predicate":"draftMessage","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.1?true"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"message","type":"string"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"},{"name":"date","type":"int"}],"type":"DraftMessage"},{"id":"-1615153660","predicate":"messageActionHistoryClear","params":[],"type":"MessageAction"},{"id":"82699215","predicate":"messages.featuredStickersNotModified","params":[],"type":"messages.FeaturedStickers"},{"id":"-123893531","predicate":"messages.featuredStickers","params":[{"name":"hash","type":"int"},{"name":"sets","type":"Vector<StickerSetCovered>"},{"name":"unread","type":"Vector<long>"}],"type":"messages.FeaturedStickers"},{"id":"1461528386","predicate":"updateReadFeaturedStickers","params":[],"type":"Update"},{"id":"186120336","predicate":"messages.recentStickersNotModified","params":[],"type":"messages.RecentStickers"},{"id":"586395571","predicate":"messages.recentStickers","params":[{"name":"hash","type":"int"},{"name":"packs","type":"Vector<StickerPack>"},{"name":"stickers","type":"Vector<Document>"},{"name":"dates","type":"Vector<int>"}],"type":"messages.RecentStickers"},{"id":"-1706939360","predicate":"updateRecentStickers","params":[],"type":"Update"},{"id":"1338747336","predicate":"messages.archivedStickers","params":[{"name":"count","type":"int"},{"name":"sets","type":"Vector<StickerSetCovered>"}],"type":"messages.ArchivedStickers"},{"id":"946083368","predicate":"messages.stickerSetInstallResultSuccess","params":[],"type":"messages.StickerSetInstallResult"},{"id":"904138920","predicate":"messages.stickerSetInstallResultArchive","params":[{"name":"sets","type":"Vector<StickerSetCovered>"}],"type":"messages.StickerSetInstallResult"},{"id":"1678812626","predicate":"stickerSetCovered","params":[{"name":"set","type":"StickerSet"},{"name":"cover","type":"Document"}],"type":"StickerSetCovered"},{"id":"-1574314746","predicate":"updateConfig","params":[],"type":"Update"},{"id":"861169551","predicate":"updatePtsChanged","params":[],"type":"Update"},{"id":"-440664550","predicate":"inputMediaPhotoExternal","params":[{"name":"flags","type":"#"},{"name":"url","type":"string"},{"name":"ttl_seconds","type":"flags.0?int"}],"type":"InputMedia"},{"id":"-78455655","predicate":"inputMediaDocumentExternal","params":[{"name":"flags","type":"#"},{"name":"url","type":"string"},{"name":"ttl_seconds","type":"flags.0?int"}],"type":"InputMedia"},{"id":"872932635","predicate":"stickerSetMultiCovered","params":[{"name":"set","type":"StickerSet"},{"name":"covers","type":"Vector<Document>"}],"type":"StickerSetCovered"},{"id":"-1361650766","predicate":"maskCoords","params":[{"name":"n","type":"int"},{"name":"x","type":"double"},{"name":"y","type":"double"},{"name":"zoom","type":"double"}],"type":"MaskCoords"},{"id":"-1744710921","predicate":"documentAttributeHasStickers","params":[],"type":"DocumentAttribute"},{"id":"1251549527","predicate":"inputStickeredMediaPhoto","params":[{"name":"id","type":"InputPhoto"}],"type":"InputStickeredMedia"},{"id":"70813275","predicate":"inputStickeredMediaDocument","params":[{"name":"id","type":"InputDocument"}],"type":"InputStickeredMedia"},{"id":"-1107729093","predicate":"game","params":[{"name":"flags","type":"#"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"short_name","type":"string"},{"name":"title","type":"string"},{"name":"description","type":"string"},{"name":"photo","type":"Photo"},{"name":"document","type":"flags.0?Document"}],"type":"Game"},{"id":"1336154098","predicate":"inputBotInlineResultGame","params":[{"name":"id","type":"string"},{"name":"short_name","type":"string"},{"name":"send_message","type":"InputBotInlineMessage"}],"type":"InputBotInlineResult"},{"id":"1262639204","predicate":"inputBotInlineMessageGame","params":[{"name":"flags","type":"#"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"}],"type":"InputBotInlineMessage"},{"id":"-38694904","predicate":"messageMediaGame","params":[{"name":"game","type":"Game"}],"type":"MessageMedia"},{"id":"-750828557","predicate":"inputMediaGame","params":[{"name":"id","type":"InputGame"}],"type":"InputMedia"},{"id":"53231223","predicate":"inputGameID","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputGame"},{"id":"-1020139510","predicate":"inputGameShortName","params":[{"name":"bot_id","type":"InputUser"},{"name":"short_name","type":"string"}],"type":"InputGame"},{"id":"1358175439","predicate":"keyboardButtonGame","params":[{"name":"text","type":"string"}],"type":"KeyboardButton"},{"id":"-1834538890","predicate":"messageActionGameScore","params":[{"name":"game_id","type":"long"},{"name":"score","type":"int"}],"type":"MessageAction"},{"id":"1493171408","predicate":"highScore","params":[{"name":"pos","type":"int"},{"name":"user_id","type":"int"},{"name":"score","type":"int"}],"type":"HighScore"},{"id":"-1707344487","predicate":"messages.highScores","params":[{"name":"scores","type":"Vector<HighScore>"},{"name":"users","type":"Vector<User>"}],"type":"messages.HighScores"},{"id":"1258196845","predicate":"updates.differenceTooLong","params":[{"name":"pts","type":"int"}],"type":"updates.Difference"},{"id":"1081547008","predicate":"updateChannelWebPage","params":[{"name":"channel_id","type":"int"},{"name":"webpage","type":"WebPage"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"-1663561404","predicate":"messages.chatsSlice","params":[{"name":"count","type":"int"},{"name":"chats","type":"Vector<Chat>"}],"type":"messages.Chats"},{"id":"-599948721","predicate":"textEmpty","params":[],"type":"RichText"},{"id":"1950782688","predicate":"textPlain","params":[{"name":"text","type":"string"}],"type":"RichText"},{"id":"1730456516","predicate":"textBold","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"-653089380","predicate":"textItalic","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"-1054465340","predicate":"textUnderline","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"-1678197867","predicate":"textStrike","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"1816074681","predicate":"textFixed","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"1009288385","predicate":"textUrl","params":[{"name":"text","type":"RichText"},{"name":"url","type":"string"},{"name":"webpage_id","type":"long"}],"type":"RichText"},{"id":"-564523562","predicate":"textEmail","params":[{"name":"text","type":"RichText"},{"name":"email","type":"string"}],"type":"RichText"},{"id":"2120376535","predicate":"textConcat","params":[{"name":"texts","type":"Vector<RichText>"}],"type":"RichText"},{"id":"324435594","predicate":"pageBlockUnsupported","params":[],"type":"PageBlock"},{"id":"1890305021","predicate":"pageBlockTitle","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"-1879401953","predicate":"pageBlockSubtitle","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"-1162877472","predicate":"pageBlockAuthorDate","params":[{"name":"author","type":"RichText"},{"name":"published_date","type":"int"}],"type":"PageBlock"},{"id":"-1076861716","predicate":"pageBlockHeader","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"-248793375","predicate":"pageBlockSubheader","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"1182402406","predicate":"pageBlockParagraph","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"-1066346178","predicate":"pageBlockPreformatted","params":[{"name":"text","type":"RichText"},{"name":"language","type":"string"}],"type":"PageBlock"},{"id":"1216809369","predicate":"pageBlockFooter","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"-618614392","predicate":"pageBlockDivider","params":[],"type":"PageBlock"},{"id":"-837994576","predicate":"pageBlockAnchor","params":[{"name":"name","type":"string"}],"type":"PageBlock"},{"id":"-454524911","predicate":"pageBlockList","params":[{"name":"items","type":"Vector<PageListItem>"}],"type":"PageBlock"},{"id":"641563686","predicate":"pageBlockBlockquote","params":[{"name":"text","type":"RichText"},{"name":"caption","type":"RichText"}],"type":"PageBlock"},{"id":"1329878739","predicate":"pageBlockPullquote","params":[{"name":"text","type":"RichText"},{"name":"caption","type":"RichText"}],"type":"PageBlock"},{"id":"391759200","predicate":"pageBlockPhoto","params":[{"name":"flags","type":"#"},{"name":"photo_id","type":"long"},{"name":"caption","type":"PageCaption"},{"name":"url","type":"flags.0?string"},{"name":"webpage_id","type":"flags.0?long"}],"type":"PageBlock"},{"id":"2089805750","predicate":"pageBlockVideo","params":[{"name":"flags","type":"#"},{"name":"autoplay","type":"flags.0?true"},{"name":"loop","type":"flags.1?true"},{"name":"video_id","type":"long"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"972174080","predicate":"pageBlockCover","params":[{"name":"cover","type":"PageBlock"}],"type":"PageBlock"},{"id":"-1468953147","predicate":"pageBlockEmbed","params":[{"name":"flags","type":"#"},{"name":"full_width","type":"flags.0?true"},{"name":"allow_scrolling","type":"flags.3?true"},{"name":"url","type":"flags.1?string"},{"name":"html","type":"flags.2?string"},{"name":"poster_photo_id","type":"flags.4?long"},{"name":"w","type":"flags.5?int"},{"name":"h","type":"flags.5?int"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"-229005301","predicate":"pageBlockEmbedPost","params":[{"name":"url","type":"string"},{"name":"webpage_id","type":"long"},{"name":"author_photo_id","type":"long"},{"name":"author","type":"string"},{"name":"date","type":"int"},{"name":"blocks","type":"Vector<PageBlock>"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"1705048653","predicate":"pageBlockCollage","params":[{"name":"items","type":"Vector<PageBlock>"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"52401552","predicate":"pageBlockSlideshow","params":[{"name":"items","type":"Vector<PageBlock>"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"-2054908813","predicate":"webPageNotModified","params":[],"type":"WebPage"},{"id":"-88417185","predicate":"inputPrivacyKeyPhoneCall","params":[],"type":"InputPrivacyKey"},{"id":"1030105979","predicate":"privacyKeyPhoneCall","params":[],"type":"PrivacyKey"},{"id":"-580219064","predicate":"sendMessageGamePlayAction","params":[],"type":"SendMessageAction"},{"id":"-2048646399","predicate":"phoneCallDiscardReasonMissed","params":[],"type":"PhoneCallDiscardReason"},{"id":"-527056480","predicate":"phoneCallDiscardReasonDisconnect","params":[],"type":"PhoneCallDiscardReason"},{"id":"1471006352","predicate":"phoneCallDiscardReasonHangup","params":[],"type":"PhoneCallDiscardReason"},{"id":"-84416311","predicate":"phoneCallDiscardReasonBusy","params":[],"type":"PhoneCallDiscardReason"},{"id":"1852826908","predicate":"updateDialogPinned","params":[{"name":"flags","type":"#"},{"name":"pinned","type":"flags.0?true"},{"name":"folder_id","type":"flags.1?int"},{"name":"peer","type":"DialogPeer"}],"type":"Update"},{"id":"-99664734","predicate":"updatePinnedDialogs","params":[{"name":"flags","type":"#"},{"name":"folder_id","type":"flags.1?int"},{"name":"order","type":"flags.0?Vector<DialogPeer>"}],"type":"Update"},{"id":"2104790276","predicate":"dataJSON","params":[{"name":"data","type":"string"}],"type":"DataJSON"},{"id":"-2095595325","predicate":"updateBotWebhookJSON","params":[{"name":"data","type":"DataJSON"}],"type":"Update"},{"id":"-1684914010","predicate":"updateBotWebhookJSONQuery","params":[{"name":"query_id","type":"long"},{"name":"data","type":"DataJSON"},{"name":"timeout","type":"int"}],"type":"Update"},{"id":"-886477832","predicate":"labeledPrice","params":[{"name":"label","type":"string"},{"name":"amount","type":"long"}],"type":"LabeledPrice"},{"id":"-1022713000","predicate":"invoice","params":[{"name":"flags","type":"#"},{"name":"test","type":"flags.0?true"},{"name":"name_requested","type":"flags.1?true"},{"name":"phone_requested","type":"flags.2?true"},{"name":"email_requested","type":"flags.3?true"},{"name":"shipping_address_requested","type":"flags.4?true"},{"name":"flexible","type":"flags.5?true"},{"name":"phone_to_provider","type":"flags.6?true"},{"name":"email_to_provider","type":"flags.7?true"},{"name":"currency","type":"string"},{"name":"prices","type":"Vector<LabeledPrice>"}],"type":"Invoice"},{"id":"-186607933","predicate":"inputMediaInvoice","params":[{"name":"flags","type":"#"},{"name":"title","type":"string"},{"name":"description","type":"string"},{"name":"photo","type":"flags.0?InputWebDocument"},{"name":"invoice","type":"Invoice"},{"name":"payload","type":"bytes"},{"name":"provider","type":"string"},{"name":"provider_data","type":"DataJSON"},{"name":"start_param","type":"string"}],"type":"InputMedia"},{"id":"-368917890","predicate":"paymentCharge","params":[{"name":"id","type":"string"},{"name":"provider_charge_id","type":"string"}],"type":"PaymentCharge"},{"id":"-1892568281","predicate":"messageActionPaymentSentMe","params":[{"name":"flags","type":"#"},{"name":"currency","type":"string"},{"name":"total_amount","type":"long"},{"name":"payload","type":"bytes"},{"name":"info","type":"flags.0?PaymentRequestedInfo"},{"name":"shipping_option_id","type":"flags.1?string"},{"name":"charge","type":"PaymentCharge"}],"type":"MessageAction"},{"id":"-2074799289","predicate":"messageMediaInvoice","params":[{"name":"flags","type":"#"},{"name":"shipping_address_requested","type":"flags.1?true"},{"name":"test","type":"flags.3?true"},{"name":"title","type":"string"},{"name":"description","type":"string"},{"name":"photo","type":"flags.0?WebDocument"},{"name":"receipt_msg_id","type":"flags.2?int"},{"name":"currency","type":"string"},{"name":"total_amount","type":"long"},{"name":"start_param","type":"string"}],"type":"MessageMedia"},{"id":"512535275","predicate":"postAddress","params":[{"name":"street_line1","type":"string"},{"name":"street_line2","type":"string"},{"name":"city","type":"string"},{"name":"state","type":"string"},{"name":"country_iso2","type":"string"},{"name":"post_code","type":"string"}],"type":"PostAddress"},{"id":"-1868808300","predicate":"paymentRequestedInfo","params":[{"name":"flags","type":"#"},{"name":"name","type":"flags.0?string"},{"name":"phone","type":"flags.1?string"},{"name":"email","type":"flags.2?string"},{"name":"shipping_address","type":"flags.3?PostAddress"}],"type":"PaymentRequestedInfo"},{"id":"-1344716869","predicate":"keyboardButtonBuy","params":[{"name":"text","type":"string"}],"type":"KeyboardButton"},{"id":"1080663248","predicate":"messageActionPaymentSent","params":[{"name":"currency","type":"string"},{"name":"total_amount","type":"long"}],"type":"MessageAction"},{"id":"-842892769","predicate":"paymentSavedCredentialsCard","params":[{"name":"id","type":"string"},{"name":"title","type":"string"}],"type":"PaymentSavedCredentials"},{"id":"475467473","predicate":"webDocument","params":[{"name":"url","type":"string"},{"name":"access_hash","type":"long"},{"name":"size","type":"int"},{"name":"mime_type","type":"string"},{"name":"attributes","type":"Vector<DocumentAttribute>"}],"type":"WebDocument"},{"id":"-1678949555","predicate":"inputWebDocument","params":[{"name":"url","type":"string"},{"name":"size","type":"int"},{"name":"mime_type","type":"string"},{"name":"attributes","type":"Vector<DocumentAttribute>"}],"type":"InputWebDocument"},{"id":"-1036396922","predicate":"inputWebFileLocation","params":[{"name":"url","type":"string"},{"name":"access_hash","type":"long"}],"type":"InputWebFileLocation"},{"id":"568808380","predicate":"upload.webFile","params":[{"name":"size","type":"int"},{"name":"mime_type","type":"string"},{"name":"file_type","type":"storage.FileType"},{"name":"mtime","type":"int"},{"name":"bytes","type":"bytes"}],"type":"upload.WebFile"},{"id":"1062645411","predicate":"payments.paymentForm","params":[{"name":"flags","type":"#"},{"name":"can_save_credentials","type":"flags.2?true"},{"name":"password_missing","type":"flags.3?true"},{"name":"bot_id","type":"int"},{"name":"invoice","type":"Invoice"},{"name":"provider_id","type":"int"},{"name":"url","type":"string"},{"name":"native_provider","type":"flags.4?string"},{"name":"native_params","type":"flags.4?DataJSON"},{"name":"saved_info","type":"flags.0?PaymentRequestedInfo"},{"name":"saved_credentials","type":"flags.1?PaymentSavedCredentials"},{"name":"users","type":"Vector<User>"}],"type":"payments.PaymentForm"},{"id":"-784000893","predicate":"payments.validatedRequestedInfo","params":[{"name":"flags","type":"#"},{"name":"id","type":"flags.0?string"},{"name":"shipping_options","type":"flags.1?Vector<ShippingOption>"}],"type":"payments.ValidatedRequestedInfo"},{"id":"1314881805","predicate":"payments.paymentResult","params":[{"name":"updates","type":"Updates"}],"type":"payments.PaymentResult"},{"id":"1342771681","predicate":"payments.paymentReceipt","params":[{"name":"flags","type":"#"},{"name":"date","type":"int"},{"name":"bot_id","type":"int"},{"name":"invoice","type":"Invoice"},{"name":"provider_id","type":"int"},{"name":"info","type":"flags.0?PaymentRequestedInfo"},{"name":"shipping","type":"flags.1?ShippingOption"},{"name":"currency","type":"string"},{"name":"total_amount","type":"long"},{"name":"credentials_title","type":"string"},{"name":"users","type":"Vector<User>"}],"type":"payments.PaymentReceipt"},{"id":"-74456004","predicate":"payments.savedInfo","params":[{"name":"flags","type":"#"},{"name":"has_saved_credentials","type":"flags.1?true"},{"name":"saved_info","type":"flags.0?PaymentRequestedInfo"}],"type":"payments.SavedInfo"},{"id":"-1056001329","predicate":"inputPaymentCredentialsSaved","params":[{"name":"id","type":"string"},{"name":"tmp_password","type":"bytes"}],"type":"InputPaymentCredentials"},{"id":"873977640","predicate":"inputPaymentCredentials","params":[{"name":"flags","type":"#"},{"name":"save","type":"flags.0?true"},{"name":"data","type":"DataJSON"}],"type":"InputPaymentCredentials"},{"id":"-614138572","predicate":"account.tmpPassword","params":[{"name":"tmp_password","type":"bytes"},{"name":"valid_until","type":"int"}],"type":"account.TmpPassword"},{"id":"-1239335713","predicate":"shippingOption","params":[{"name":"id","type":"string"},{"name":"title","type":"string"},{"name":"prices","type":"Vector<LabeledPrice>"}],"type":"ShippingOption"},{"id":"-523384512","predicate":"updateBotShippingQuery","params":[{"name":"query_id","type":"long"},{"name":"user_id","type":"int"},{"name":"payload","type":"bytes"},{"name":"shipping_address","type":"PostAddress"}],"type":"Update"},{"id":"1563376297","predicate":"updateBotPrecheckoutQuery","params":[{"name":"flags","type":"#"},{"name":"query_id","type":"long"},{"name":"user_id","type":"int"},{"name":"payload","type":"bytes"},{"name":"info","type":"flags.0?PaymentRequestedInfo"},{"name":"shipping_option_id","type":"flags.1?string"},{"name":"currency","type":"string"},{"name":"total_amount","type":"long"}],"type":"Update"},{"id":"-6249322","predicate":"inputStickerSetItem","params":[{"name":"flags","type":"#"},{"name":"document","type":"InputDocument"},{"name":"emoji","type":"string"},{"name":"mask_coords","type":"flags.0?MaskCoords"}],"type":"InputStickerSetItem"},{"id":"-1425052898","predicate":"updatePhoneCall","params":[{"name":"phone_call","type":"PhoneCall"}],"type":"Update"},{"id":"506920429","predicate":"inputPhoneCall","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputPhoneCall"},{"id":"1399245077","predicate":"phoneCallEmpty","params":[{"name":"id","type":"long"}],"type":"PhoneCall"},{"id":"462375633","predicate":"phoneCallWaiting","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.5?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"protocol","type":"PhoneCallProtocol"},{"name":"receive_date","type":"flags.0?int"}],"type":"PhoneCall"},{"id":"-2014659757","predicate":"phoneCallRequested","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.5?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"g_a_hash","type":"bytes"},{"name":"protocol","type":"PhoneCallProtocol"}],"type":"PhoneCall"},{"id":"-1719909046","predicate":"phoneCallAccepted","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.5?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"g_b","type":"bytes"},{"name":"protocol","type":"PhoneCallProtocol"}],"type":"PhoneCall"},{"id":"-2025673089","predicate":"phoneCall","params":[{"name":"flags","type":"#"},{"name":"p2p_allowed","type":"flags.5?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"date","type":"int"},{"name":"admin_id","type":"int"},{"name":"participant_id","type":"int"},{"name":"g_a_or_b","type":"bytes"},{"name":"key_fingerprint","type":"long"},{"name":"protocol","type":"PhoneCallProtocol"},{"name":"connections","type":"Vector<PhoneConnection>"},{"name":"start_date","type":"int"}],"type":"PhoneCall"},{"id":"1355435489","predicate":"phoneCallDiscarded","params":[{"name":"flags","type":"#"},{"name":"need_rating","type":"flags.2?true"},{"name":"need_debug","type":"flags.3?true"},{"name":"video","type":"flags.5?true"},{"name":"id","type":"long"},{"name":"reason","type":"flags.0?PhoneCallDiscardReason"},{"name":"duration","type":"flags.1?int"}],"type":"PhoneCall"},{"id":"-1655957568","predicate":"phoneConnection","params":[{"name":"id","type":"long"},{"name":"ip","type":"string"},{"name":"ipv6","type":"string"},{"name":"port","type":"int"},{"name":"peer_tag","type":"bytes"}],"type":"PhoneConnection"},{"id":"-1564789301","predicate":"phoneCallProtocol","params":[{"name":"flags","type":"#"},{"name":"udp_p2p","type":"flags.0?true"},{"name":"udp_reflector","type":"flags.1?true"},{"name":"min_layer","type":"int"},{"name":"max_layer","type":"int"}],"type":"PhoneCallProtocol"},{"id":"-326966976","predicate":"phone.phoneCall","params":[{"name":"phone_call","type":"PhoneCall"},{"name":"users","type":"Vector<User>"}],"type":"phone.PhoneCall"},{"id":"-2134272152","predicate":"inputMessagesFilterPhoneCalls","params":[{"name":"flags","type":"#"},{"name":"missed","type":"flags.0?true"}],"type":"MessagesFilter"},{"id":"-2132731265","predicate":"messageActionPhoneCall","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.2?true"},{"name":"call_id","type":"long"},{"name":"reason","type":"flags.0?PhoneCallDiscardReason"},{"name":"duration","type":"flags.1?int"}],"type":"MessageAction"},{"id":"2054952868","predicate":"inputMessagesFilterRoundVoice","params":[],"type":"MessagesFilter"},{"id":"-1253451181","predicate":"inputMessagesFilterRoundVideo","params":[],"type":"MessagesFilter"},{"id":"-1997373508","predicate":"sendMessageRecordRoundAction","params":[],"type":"SendMessageAction"},{"id":"608050278","predicate":"sendMessageUploadRoundAction","params":[{"name":"progress","type":"int"}],"type":"SendMessageAction"},{"id":"-242427324","predicate":"upload.fileCdnRedirect","params":[{"name":"dc_id","type":"int"},{"name":"file_token","type":"bytes"},{"name":"encryption_key","type":"bytes"},{"name":"encryption_iv","type":"bytes"},{"name":"file_hashes","type":"Vector<FileHash>"}],"type":"upload.File"},{"id":"-290921362","predicate":"upload.cdnFileReuploadNeeded","params":[{"name":"request_token","type":"bytes"}],"type":"upload.CdnFile"},{"id":"-1449145777","predicate":"upload.cdnFile","params":[{"name":"bytes","type":"bytes"}],"type":"upload.CdnFile"},{"id":"-914167110","predicate":"cdnPublicKey","params":[{"name":"dc_id","type":"int"},{"name":"public_key","type":"string"}],"type":"CdnPublicKey"},{"id":"1462101002","predicate":"cdnConfig","params":[{"name":"public_keys","type":"Vector<CdnPublicKey>"}],"type":"CdnConfig"},{"id":"-283684427","predicate":"pageBlockChannel","params":[{"name":"channel","type":"Chat"}],"type":"PageBlock"},{"id":"-892239370","predicate":"langPackString","params":[{"name":"key","type":"string"},{"name":"value","type":"string"}],"type":"LangPackString"},{"id":"1816636575","predicate":"langPackStringPluralized","params":[{"name":"flags","type":"#"},{"name":"key","type":"string"},{"name":"zero_value","type":"flags.0?string"},{"name":"one_value","type":"flags.1?string"},{"name":"two_value","type":"flags.2?string"},{"name":"few_value","type":"flags.3?string"},{"name":"many_value","type":"flags.4?string"},{"name":"other_value","type":"string"}],"type":"LangPackString"},{"id":"695856818","predicate":"langPackStringDeleted","params":[{"name":"key","type":"string"}],"type":"LangPackString"},{"id":"-209337866","predicate":"langPackDifference","params":[{"name":"lang_code","type":"string"},{"name":"from_version","type":"int"},{"name":"version","type":"int"},{"name":"strings","type":"Vector<LangPackString>"}],"type":"LangPackDifference"},{"id":"-288727837","predicate":"langPackLanguage","params":[{"name":"flags","type":"#"},{"name":"official","type":"flags.0?true"},{"name":"rtl","type":"flags.2?true"},{"name":"beta","type":"flags.3?true"},{"name":"name","type":"string"},{"name":"native_name","type":"string"},{"name":"lang_code","type":"string"},{"name":"base_lang_code","type":"flags.1?string"},{"name":"plural_code","type":"string"},{"name":"strings_count","type":"int"},{"name":"translated_count","type":"int"},{"name":"translations_url","type":"string"}],"type":"LangPackLanguage"},{"id":"1180041828","predicate":"updateLangPackTooLong","params":[{"name":"lang_code","type":"string"}],"type":"Update"},{"id":"1442983757","predicate":"updateLangPack","params":[{"name":"difference","type":"LangPackDifference"}],"type":"Update"},{"id":"-859915345","predicate":"channelParticipantAdmin","params":[{"name":"flags","type":"#"},{"name":"can_edit","type":"flags.0?true"},{"name":"self","type":"flags.1?true"},{"name":"user_id","type":"int"},{"name":"inviter_id","type":"flags.1?int"},{"name":"promoted_by","type":"int"},{"name":"date","type":"int"},{"name":"admin_rights","type":"ChatAdminRights"},{"name":"rank","type":"flags.2?string"}],"type":"ChannelParticipant"},{"id":"470789295","predicate":"channelParticipantBanned","params":[{"name":"flags","type":"#"},{"name":"left","type":"flags.0?true"},{"name":"user_id","type":"int"},{"name":"kicked_by","type":"int"},{"name":"date","type":"int"},{"name":"banned_rights","type":"ChatBannedRights"}],"type":"ChannelParticipant"},{"id":"338142689","predicate":"channelParticipantsBanned","params":[{"name":"q","type":"string"}],"type":"ChannelParticipantsFilter"},{"id":"106343499","predicate":"channelParticipantsSearch","params":[{"name":"q","type":"string"}],"type":"ChannelParticipantsFilter"},{"id":"-421545947","predicate":"channelAdminLogEventActionChangeTitle","params":[{"name":"prev_value","type":"string"},{"name":"new_value","type":"string"}],"type":"ChannelAdminLogEventAction"},{"id":"1427671598","predicate":"channelAdminLogEventActionChangeAbout","params":[{"name":"prev_value","type":"string"},{"name":"new_value","type":"string"}],"type":"ChannelAdminLogEventAction"},{"id":"1783299128","predicate":"channelAdminLogEventActionChangeUsername","params":[{"name":"prev_value","type":"string"},{"name":"new_value","type":"string"}],"type":"ChannelAdminLogEventAction"},{"id":"1129042607","predicate":"channelAdminLogEventActionChangePhoto","params":[{"name":"prev_photo","type":"Photo"},{"name":"new_photo","type":"Photo"}],"type":"ChannelAdminLogEventAction"},{"id":"460916654","predicate":"channelAdminLogEventActionToggleInvites","params":[{"name":"new_value","type":"Bool"}],"type":"ChannelAdminLogEventAction"},{"id":"648939889","predicate":"channelAdminLogEventActionToggleSignatures","params":[{"name":"new_value","type":"Bool"}],"type":"ChannelAdminLogEventAction"},{"id":"-370660328","predicate":"channelAdminLogEventActionUpdatePinned","params":[{"name":"message","type":"Message"}],"type":"ChannelAdminLogEventAction"},{"id":"1889215493","predicate":"channelAdminLogEventActionEditMessage","params":[{"name":"prev_message","type":"Message"},{"name":"new_message","type":"Message"}],"type":"ChannelAdminLogEventAction"},{"id":"1121994683","predicate":"channelAdminLogEventActionDeleteMessage","params":[{"name":"message","type":"Message"}],"type":"ChannelAdminLogEventAction"},{"id":"405815507","predicate":"channelAdminLogEventActionParticipantJoin","params":[],"type":"ChannelAdminLogEventAction"},{"id":"-124291086","predicate":"channelAdminLogEventActionParticipantLeave","params":[],"type":"ChannelAdminLogEventAction"},{"id":"-484690728","predicate":"channelAdminLogEventActionParticipantInvite","params":[{"name":"participant","type":"ChannelParticipant"}],"type":"ChannelAdminLogEventAction"},{"id":"-422036098","predicate":"channelAdminLogEventActionParticipantToggleBan","params":[{"name":"prev_participant","type":"ChannelParticipant"},{"name":"new_participant","type":"ChannelParticipant"}],"type":"ChannelAdminLogEventAction"},{"id":"-714643696","predicate":"channelAdminLogEventActionParticipantToggleAdmin","params":[{"name":"prev_participant","type":"ChannelParticipant"},{"name":"new_participant","type":"ChannelParticipant"}],"type":"ChannelAdminLogEventAction"},{"id":"995769920","predicate":"channelAdminLogEvent","params":[{"name":"id","type":"long"},{"name":"date","type":"int"},{"name":"user_id","type":"int"},{"name":"action","type":"ChannelAdminLogEventAction"}],"type":"ChannelAdminLogEvent"},{"id":"-309659827","predicate":"channels.adminLogResults","params":[{"name":"events","type":"Vector<ChannelAdminLogEvent>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"channels.AdminLogResults"},{"id":"-368018716","predicate":"channelAdminLogEventsFilter","params":[{"name":"flags","type":"#"},{"name":"join","type":"flags.0?true"},{"name":"leave","type":"flags.1?true"},{"name":"invite","type":"flags.2?true"},{"name":"ban","type":"flags.3?true"},{"name":"unban","type":"flags.4?true"},{"name":"kick","type":"flags.5?true"},{"name":"unkick","type":"flags.6?true"},{"name":"promote","type":"flags.7?true"},{"name":"demote","type":"flags.8?true"},{"name":"info","type":"flags.9?true"},{"name":"settings","type":"flags.10?true"},{"name":"pinned","type":"flags.11?true"},{"name":"edit","type":"flags.12?true"},{"name":"delete","type":"flags.13?true"}],"type":"ChannelAdminLogEventsFilter"},{"id":"511092620","predicate":"topPeerCategoryPhoneCalls","params":[],"type":"TopPeerCategory"},{"id":"-2143067670","predicate":"pageBlockAudio","params":[{"name":"audio_id","type":"long"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"1558266229","predicate":"popularContact","params":[{"name":"client_id","type":"long"},{"name":"importers","type":"int"}],"type":"PopularContact"},{"id":"1200788123","predicate":"messageActionScreenshotTaken","params":[],"type":"MessageAction"},{"id":"-1634752813","predicate":"messages.favedStickersNotModified","params":[],"type":"messages.FavedStickers"},{"id":"-209768682","predicate":"messages.favedStickers","params":[{"name":"hash","type":"int"},{"name":"packs","type":"Vector<StickerPack>"},{"name":"stickers","type":"Vector<Document>"}],"type":"messages.FavedStickers"},{"id":"-451831443","predicate":"updateFavedStickers","params":[],"type":"Update"},{"id":"-1987495099","predicate":"updateChannelReadMessagesContents","params":[{"name":"channel_id","type":"int"},{"name":"messages","type":"Vector<int>"}],"type":"Update"},{"id":"-1040652646","predicate":"inputMessagesFilterMyMentions","params":[],"type":"MessagesFilter"},{"id":"1887741886","predicate":"updateContactsReset","params":[],"type":"Update"},{"id":"-1312568665","predicate":"channelAdminLogEventActionChangeStickerSet","params":[{"name":"prev_stickerset","type":"InputStickerSet"},{"name":"new_stickerset","type":"InputStickerSet"}],"type":"ChannelAdminLogEventAction"},{"id":"-85549226","predicate":"messageActionCustomAction","params":[{"name":"message","type":"string"}],"type":"MessageAction"},{"id":"178373535","predicate":"inputPaymentCredentialsApplePay","params":[{"name":"payment_data","type":"DataJSON"}],"type":"InputPaymentCredentials"},{"id":"-905587442","predicate":"inputPaymentCredentialsAndroidPay","params":[{"name":"payment_token","type":"DataJSON"},{"name":"google_transaction_id","type":"string"}],"type":"InputPaymentCredentials"},{"id":"-419271411","predicate":"inputMessagesFilterGeo","params":[],"type":"MessagesFilter"},{"id":"-530392189","predicate":"inputMessagesFilterContacts","params":[],"type":"MessagesFilter"},{"id":"1893427255","predicate":"updateChannelAvailableMessages","params":[{"name":"channel_id","type":"int"},{"name":"available_min_id","type":"int"}],"type":"Update"},{"id":"1599903217","predicate":"channelAdminLogEventActionTogglePreHistoryHidden","params":[{"name":"new_value","type":"Bool"}],"type":"ChannelAdminLogEventAction"},{"id":"-833715459","predicate":"inputMediaGeoLive","params":[{"name":"flags","type":"#"},{"name":"stopped","type":"flags.0?true"},{"name":"geo_point","type":"InputGeoPoint"},{"name":"period","type":"flags.1?int"}],"type":"InputMedia"},{"id":"2084316681","predicate":"messageMediaGeoLive","params":[{"name":"geo","type":"GeoPoint"},{"name":"period","type":"int"}],"type":"MessageMedia"},{"id":"1189204285","predicate":"recentMeUrlUnknown","params":[{"name":"url","type":"string"}],"type":"RecentMeUrl"},{"id":"-1917045962","predicate":"recentMeUrlUser","params":[{"name":"url","type":"string"},{"name":"user_id","type":"int"}],"type":"RecentMeUrl"},{"id":"-1608834311","predicate":"recentMeUrlChat","params":[{"name":"url","type":"string"},{"name":"chat_id","type":"int"}],"type":"RecentMeUrl"},{"id":"-347535331","predicate":"recentMeUrlChatInvite","params":[{"name":"url","type":"string"},{"name":"chat_invite","type":"ChatInvite"}],"type":"RecentMeUrl"},{"id":"-1140172836","predicate":"recentMeUrlStickerSet","params":[{"name":"url","type":"string"},{"name":"set","type":"StickerSetCovered"}],"type":"RecentMeUrl"},{"id":"235081943","predicate":"help.recentMeUrls","params":[{"name":"urls","type":"Vector<RecentMeUrl>"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"help.RecentMeUrls"},{"id":"-266911767","predicate":"channels.channelParticipantsNotModified","params":[],"type":"channels.ChannelParticipants"},{"id":"1951620897","predicate":"messages.messagesNotModified","params":[{"name":"count","type":"int"}],"type":"messages.Messages"},{"id":"482797855","predicate":"inputSingleMedia","params":[{"name":"flags","type":"#"},{"name":"media","type":"InputMedia"},{"name":"random_id","type":"long"},{"name":"message","type":"string"},{"name":"entities","type":"flags.0?Vector<MessageEntity>"}],"type":"InputSingleMedia"},{"id":"-892779534","predicate":"webAuthorization","params":[{"name":"hash","type":"long"},{"name":"bot_id","type":"int"},{"name":"domain","type":"string"},{"name":"browser","type":"string"},{"name":"platform","type":"string"},{"name":"date_created","type":"int"},{"name":"date_active","type":"int"},{"name":"ip","type":"string"},{"name":"region","type":"string"}],"type":"WebAuthorization"},{"id":"-313079300","predicate":"account.webAuthorizations","params":[{"name":"authorizations","type":"Vector<WebAuthorization>"},{"name":"users","type":"Vector<User>"}],"type":"account.WebAuthorizations"},{"id":"-1502174430","predicate":"inputMessageID","params":[{"name":"id","type":"int"}],"type":"InputMessage"},{"id":"-1160215659","predicate":"inputMessageReplyTo","params":[{"name":"id","type":"int"}],"type":"InputMessage"},{"id":"-2037963464","predicate":"inputMessagePinned","params":[],"type":"InputMessage"},{"id":"-1687559349","predicate":"messageEntityPhone","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1280209983","predicate":"messageEntityCashtag","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"-1410748418","predicate":"messageActionBotAllowed","params":[{"name":"domain","type":"string"}],"type":"MessageAction"},{"id":"-55902537","predicate":"inputDialogPeer","params":[{"name":"peer","type":"InputPeer"}],"type":"InputDialogPeer"},{"id":"-445792507","predicate":"dialogPeer","params":[{"name":"peer","type":"Peer"}],"type":"DialogPeer"},{"id":"223655517","predicate":"messages.foundStickerSetsNotModified","params":[],"type":"messages.FoundStickerSets"},{"id":"1359533640","predicate":"messages.foundStickerSets","params":[{"name":"hash","type":"int"},{"name":"sets","type":"Vector<StickerSetCovered>"}],"type":"messages.FoundStickerSets"},{"id":"1648543603","predicate":"fileHash","params":[{"name":"offset","type":"int"},{"name":"limit","type":"int"},{"name":"hash","type":"bytes"}],"type":"FileHash"},{"id":"-104284986","predicate":"webDocumentNoProxy","params":[{"name":"url","type":"string"},{"name":"size","type":"int"},{"name":"mime_type","type":"string"},{"name":"attributes","type":"Vector<DocumentAttribute>"}],"type":"WebDocument"},{"id":"1968737087","predicate":"inputClientProxy","params":[{"name":"address","type":"string"},{"name":"port","type":"int"}],"type":"InputClientProxy"},{"id":"-526508104","predicate":"help.proxyDataEmpty","params":[{"name":"expires","type":"int"}],"type":"help.ProxyData"},{"id":"737668643","predicate":"help.proxyDataPromo","params":[{"name":"expires","type":"int"},{"name":"peer","type":"Peer"},{"name":"chats","type":"Vector<Chat>"},{"name":"users","type":"Vector<User>"}],"type":"help.ProxyData"},{"id":"-483352705","predicate":"help.termsOfServiceUpdateEmpty","params":[{"name":"expires","type":"int"}],"type":"help.TermsOfServiceUpdate"},{"id":"686618977","predicate":"help.termsOfServiceUpdate","params":[{"name":"expires","type":"int"},{"name":"terms_of_service","type":"help.TermsOfService"}],"type":"help.TermsOfServiceUpdate"},{"id":"859091184","predicate":"inputSecureFileUploaded","params":[{"name":"id","type":"long"},{"name":"parts","type":"int"},{"name":"md5_checksum","type":"string"},{"name":"file_hash","type":"bytes"},{"name":"secret","type":"bytes"}],"type":"InputSecureFile"},{"id":"1399317950","predicate":"inputSecureFile","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputSecureFile"},{"id":"-876089816","predicate":"inputSecureFileLocation","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputFileLocation"},{"id":"1679398724","predicate":"secureFileEmpty","params":[],"type":"SecureFile"},{"id":"-534283678","predicate":"secureFile","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"size","type":"int"},{"name":"dc_id","type":"int"},{"name":"date","type":"int"},{"name":"file_hash","type":"bytes"},{"name":"secret","type":"bytes"}],"type":"SecureFile"},{"id":"-1964327229","predicate":"secureData","params":[{"name":"data","type":"bytes"},{"name":"data_hash","type":"bytes"},{"name":"secret","type":"bytes"}],"type":"SecureData"},{"id":"2103482845","predicate":"securePlainPhone","params":[{"name":"phone","type":"string"}],"type":"SecurePlainData"},{"id":"569137759","predicate":"securePlainEmail","params":[{"name":"email","type":"string"}],"type":"SecurePlainData"},{"id":"-1658158621","predicate":"secureValueTypePersonalDetails","params":[],"type":"SecureValueType"},{"id":"1034709504","predicate":"secureValueTypePassport","params":[],"type":"SecureValueType"},{"id":"115615172","predicate":"secureValueTypeDriverLicense","params":[],"type":"SecureValueType"},{"id":"-1596951477","predicate":"secureValueTypeIdentityCard","params":[],"type":"SecureValueType"},{"id":"-1717268701","predicate":"secureValueTypeInternalPassport","params":[],"type":"SecureValueType"},{"id":"-874308058","predicate":"secureValueTypeAddress","params":[],"type":"SecureValueType"},{"id":"-63531698","predicate":"secureValueTypeUtilityBill","params":[],"type":"SecureValueType"},{"id":"-1995211763","predicate":"secureValueTypeBankStatement","params":[],"type":"SecureValueType"},{"id":"-1954007928","predicate":"secureValueTypeRentalAgreement","params":[],"type":"SecureValueType"},{"id":"-1713143702","predicate":"secureValueTypePassportRegistration","params":[],"type":"SecureValueType"},{"id":"-368907213","predicate":"secureValueTypeTemporaryRegistration","params":[],"type":"SecureValueType"},{"id":"-1289704741","predicate":"secureValueTypePhone","params":[],"type":"SecureValueType"},{"id":"-1908627474","predicate":"secureValueTypeEmail","params":[],"type":"SecureValueType"},{"id":"411017418","predicate":"secureValue","params":[{"name":"flags","type":"#"},{"name":"type","type":"SecureValueType"},{"name":"data","type":"flags.0?SecureData"},{"name":"front_side","type":"flags.1?SecureFile"},{"name":"reverse_side","type":"flags.2?SecureFile"},{"name":"selfie","type":"flags.3?SecureFile"},{"name":"translation","type":"flags.6?Vector<SecureFile>"},{"name":"files","type":"flags.4?Vector<SecureFile>"},{"name":"plain_data","type":"flags.5?SecurePlainData"},{"name":"hash","type":"bytes"}],"type":"SecureValue"},{"id":"-618540889","predicate":"inputSecureValue","params":[{"name":"flags","type":"#"},{"name":"type","type":"SecureValueType"},{"name":"data","type":"flags.0?SecureData"},{"name":"front_side","type":"flags.1?InputSecureFile"},{"name":"reverse_side","type":"flags.2?InputSecureFile"},{"name":"selfie","type":"flags.3?InputSecureFile"},{"name":"translation","type":"flags.6?Vector<InputSecureFile>"},{"name":"files","type":"flags.4?Vector<InputSecureFile>"},{"name":"plain_data","type":"flags.5?SecurePlainData"}],"type":"InputSecureValue"},{"id":"-316748368","predicate":"secureValueHash","params":[{"name":"type","type":"SecureValueType"},{"name":"hash","type":"bytes"}],"type":"SecureValueHash"},{"id":"-391902247","predicate":"secureValueErrorData","params":[{"name":"type","type":"SecureValueType"},{"name":"data_hash","type":"bytes"},{"name":"field","type":"string"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"12467706","predicate":"secureValueErrorFrontSide","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"-2037765467","predicate":"secureValueErrorReverseSide","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"-449327402","predicate":"secureValueErrorSelfie","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"2054162547","predicate":"secureValueErrorFile","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"1717706985","predicate":"secureValueErrorFiles","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"Vector<bytes>"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"871426631","predicate":"secureCredentialsEncrypted","params":[{"name":"data","type":"bytes"},{"name":"hash","type":"bytes"},{"name":"secret","type":"bytes"}],"type":"SecureCredentialsEncrypted"},{"id":"-1389486888","predicate":"account.authorizationForm","params":[{"name":"flags","type":"#"},{"name":"required_types","type":"Vector<SecureRequiredType>"},{"name":"values","type":"Vector<SecureValue>"},{"name":"errors","type":"Vector<SecureValueError>"},{"name":"users","type":"Vector<User>"},{"name":"privacy_policy_url","type":"flags.0?string"}],"type":"account.AuthorizationForm"},{"id":"-2128640689","predicate":"account.sentEmailCode","params":[{"name":"email_pattern","type":"string"},{"name":"length","type":"int"}],"type":"account.SentEmailCode"},{"id":"455635795","predicate":"messageActionSecureValuesSentMe","params":[{"name":"values","type":"Vector<SecureValue>"},{"name":"credentials","type":"SecureCredentialsEncrypted"}],"type":"MessageAction"},{"id":"-648257196","predicate":"messageActionSecureValuesSent","params":[{"name":"types","type":"Vector<SecureValueType>"}],"type":"MessageAction"},{"id":"1722786150","predicate":"help.deepLinkInfoEmpty","params":[],"type":"help.DeepLinkInfo"},{"id":"1783556146","predicate":"help.deepLinkInfo","params":[{"name":"flags","type":"#"},{"name":"update_app","type":"flags.0?true"},{"name":"message","type":"string"},{"name":"entities","type":"flags.1?Vector<MessageEntity>"}],"type":"help.DeepLinkInfo"},{"id":"289586518","predicate":"savedPhoneContact","params":[{"name":"phone","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"date","type":"int"}],"type":"SavedContact"},{"id":"1304052993","predicate":"account.takeout","params":[{"name":"id","type":"long"}],"type":"account.Takeout"},{"id":"700340377","predicate":"inputTakeoutFileLocation","params":[],"type":"InputFileLocation"},{"id":"-513517117","predicate":"updateDialogUnreadMark","params":[{"name":"flags","type":"#"},{"name":"unread","type":"flags.0?true"},{"name":"peer","type":"DialogPeer"}],"type":"Update"},{"id":"-253500010","predicate":"messages.dialogsNotModified","params":[{"name":"count","type":"int"}],"type":"messages.Dialogs"},{"id":"-1625153079","predicate":"inputWebFileGeoPointLocation","params":[{"name":"geo_point","type":"InputGeoPoint"},{"name":"access_hash","type":"long"},{"name":"w","type":"int"},{"name":"h","type":"int"},{"name":"zoom","type":"int"},{"name":"scale","type":"int"}],"type":"InputWebFileLocation"},{"id":"-1255369827","predicate":"contacts.topPeersDisabled","params":[],"type":"contacts.TopPeers"},{"id":"-1685456582","predicate":"inputReportReasonCopyright","params":[],"type":"ReportReason"},{"id":"-732254058","predicate":"passwordKdfAlgoUnknown","params":[],"type":"PasswordKdfAlgo"},{"id":"4883767","predicate":"securePasswordKdfAlgoUnknown","params":[],"type":"SecurePasswordKdfAlgo"},{"id":"-1141711456","predicate":"securePasswordKdfAlgoPBKDF2HMACSHA512iter100000","params":[{"name":"salt","type":"bytes"}],"type":"SecurePasswordKdfAlgo"},{"id":"-2042159726","predicate":"securePasswordKdfAlgoSHA512","params":[{"name":"salt","type":"bytes"}],"type":"SecurePasswordKdfAlgo"},{"id":"354925740","predicate":"secureSecretSettings","params":[{"name":"secure_algo","type":"SecurePasswordKdfAlgo"},{"name":"secure_secret","type":"bytes"},{"name":"secure_secret_id","type":"long"}],"type":"SecureSecretSettings"},{"id":"982592842","predicate":"passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow","params":[{"name":"salt1","type":"bytes"},{"name":"salt2","type":"bytes"},{"name":"g","type":"int"},{"name":"p","type":"bytes"}],"type":"PasswordKdfAlgo"},{"id":"-1736378792","predicate":"inputCheckPasswordEmpty","params":[],"type":"InputCheckPasswordSRP"},{"id":"-763367294","predicate":"inputCheckPasswordSRP","params":[{"name":"srp_id","type":"long"},{"name":"A","type":"bytes"},{"name":"M1","type":"bytes"}],"type":"InputCheckPasswordSRP"},{"id":"-2036501105","predicate":"secureValueError","params":[{"name":"type","type":"SecureValueType"},{"name":"hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"-1592506512","predicate":"secureValueErrorTranslationFile","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"bytes"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"878931416","predicate":"secureValueErrorTranslationFiles","params":[{"name":"type","type":"SecureValueType"},{"name":"file_hash","type":"Vector<bytes>"},{"name":"text","type":"string"}],"type":"SecureValueError"},{"id":"-2103600678","predicate":"secureRequiredType","params":[{"name":"flags","type":"#"},{"name":"native_names","type":"flags.0?true"},{"name":"selfie_required","type":"flags.1?true"},{"name":"translation_required","type":"flags.2?true"},{"name":"type","type":"SecureValueType"}],"type":"SecureRequiredType"},{"id":"41187252","predicate":"secureRequiredTypeOneOf","params":[{"name":"types","type":"Vector<SecureRequiredType>"}],"type":"SecureRequiredType"},{"id":"-1078332329","predicate":"help.passportConfigNotModified","params":[],"type":"help.PassportConfig"},{"id":"-1600596305","predicate":"help.passportConfig","params":[{"name":"hash","type":"int"},{"name":"countries_langs","type":"DataJSON"}],"type":"help.PassportConfig"},{"id":"488313413","predicate":"inputAppEvent","params":[{"name":"time","type":"double"},{"name":"type","type":"string"},{"name":"peer","type":"long"},{"name":"data","type":"JSONValue"}],"type":"InputAppEvent"},{"id":"-1059185703","predicate":"jsonObjectValue","params":[{"name":"key","type":"string"},{"name":"value","type":"JSONValue"}],"type":"JSONObjectValue"},{"id":"1064139624","predicate":"jsonNull","params":[],"type":"JSONValue"},{"id":"-952869270","predicate":"jsonBool","params":[{"name":"value","type":"Bool"}],"type":"JSONValue"},{"id":"736157604","predicate":"jsonNumber","params":[{"name":"value","type":"double"}],"type":"JSONValue"},{"id":"-1222740358","predicate":"jsonString","params":[{"name":"value","type":"string"}],"type":"JSONValue"},{"id":"-146520221","predicate":"jsonArray","params":[{"name":"value","type":"Vector<JSONValue>"}],"type":"JSONValue"},{"id":"-1715350371","predicate":"jsonObject","params":[{"name":"value","type":"Vector<JSONObjectValue>"}],"type":"JSONValue"},{"id":"1279515160","predicate":"updateUserPinnedMessage","params":[{"name":"user_id","type":"int"},{"name":"id","type":"int"}],"type":"Update"},{"id":"-519195831","predicate":"updateChatPinnedMessage","params":[{"name":"chat_id","type":"int"},{"name":"id","type":"int"},{"name":"version","type":"int"}],"type":"Update"},{"id":"-1311015810","predicate":"inputNotifyBroadcasts","params":[],"type":"InputNotifyPeer"},{"id":"-703403793","predicate":"notifyBroadcasts","params":[],"type":"NotifyPeer"},{"id":"-311786236","predicate":"textSubscript","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"-939827711","predicate":"textSuperscript","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"55281185","predicate":"textMarked","params":[{"name":"text","type":"RichText"}],"type":"RichText"},{"id":"483104362","predicate":"textPhone","params":[{"name":"text","type":"RichText"},{"name":"phone","type":"string"}],"type":"RichText"},{"id":"136105807","predicate":"textImage","params":[{"name":"document_id","type":"long"},{"name":"w","type":"int"},{"name":"h","type":"int"}],"type":"RichText"},{"id":"504660880","predicate":"pageBlockKicker","params":[{"name":"text","type":"RichText"}],"type":"PageBlock"},{"id":"878078826","predicate":"pageTableCell","params":[{"name":"flags","type":"#"},{"name":"header","type":"flags.0?true"},{"name":"align_center","type":"flags.3?true"},{"name":"align_right","type":"flags.4?true"},{"name":"valign_middle","type":"flags.5?true"},{"name":"valign_bottom","type":"flags.6?true"},{"name":"text","type":"flags.7?RichText"},{"name":"colspan","type":"flags.1?int"},{"name":"rowspan","type":"flags.2?int"}],"type":"PageTableCell"},{"id":"-524237339","predicate":"pageTableRow","params":[{"name":"cells","type":"Vector<PageTableCell>"}],"type":"PageTableRow"},{"id":"-1085412734","predicate":"pageBlockTable","params":[{"name":"flags","type":"#"},{"name":"bordered","type":"flags.0?true"},{"name":"striped","type":"flags.1?true"},{"name":"title","type":"RichText"},{"name":"rows","type":"Vector<PageTableRow>"}],"type":"PageBlock"},{"id":"1869903447","predicate":"pageCaption","params":[{"name":"text","type":"RichText"},{"name":"credit","type":"RichText"}],"type":"PageCaption"},{"id":"-1188055347","predicate":"pageListItemText","params":[{"name":"text","type":"RichText"}],"type":"PageListItem"},{"id":"635466748","predicate":"pageListItemBlocks","params":[{"name":"blocks","type":"Vector<PageBlock>"}],"type":"PageListItem"},{"id":"1577484359","predicate":"pageListOrderedItemText","params":[{"name":"num","type":"string"},{"name":"text","type":"RichText"}],"type":"PageListOrderedItem"},{"id":"-1730311882","predicate":"pageListOrderedItemBlocks","params":[{"name":"num","type":"string"},{"name":"blocks","type":"Vector<PageBlock>"}],"type":"PageListOrderedItem"},{"id":"-1702174239","predicate":"pageBlockOrderedList","params":[{"name":"items","type":"Vector<PageListOrderedItem>"}],"type":"PageBlock"},{"id":"1987480557","predicate":"pageBlockDetails","params":[{"name":"flags","type":"#"},{"name":"open","type":"flags.0?true"},{"name":"blocks","type":"Vector<PageBlock>"},{"name":"title","type":"RichText"}],"type":"PageBlock"},{"id":"-1282352120","predicate":"pageRelatedArticle","params":[{"name":"flags","type":"#"},{"name":"url","type":"string"},{"name":"webpage_id","type":"long"},{"name":"title","type":"flags.0?string"},{"name":"description","type":"flags.1?string"},{"name":"photo_id","type":"flags.2?long"},{"name":"author","type":"flags.3?string"},{"name":"published_date","type":"flags.4?int"}],"type":"PageRelatedArticle"},{"id":"370236054","predicate":"pageBlockRelatedArticles","params":[{"name":"title","type":"RichText"},{"name":"articles","type":"Vector<PageRelatedArticle>"}],"type":"PageBlock"},{"id":"-1538310410","predicate":"pageBlockMap","params":[{"name":"geo","type":"GeoPoint"},{"name":"zoom","type":"int"},{"name":"w","type":"int"},{"name":"h","type":"int"},{"name":"caption","type":"PageCaption"}],"type":"PageBlock"},{"id":"-1366746132","predicate":"page","params":[{"name":"flags","type":"#"},{"name":"part","type":"flags.0?true"},{"name":"rtl","type":"flags.1?true"},{"name":"v2","type":"flags.2?true"},{"name":"url","type":"string"},{"name":"blocks","type":"Vector<PageBlock>"},{"name":"photos","type":"Vector<Photo>"},{"name":"documents","type":"Vector<Document>"}],"type":"Page"},{"id":"-610373422","predicate":"inputPrivacyKeyPhoneP2P","params":[],"type":"InputPrivacyKey"},{"id":"961092808","predicate":"privacyKeyPhoneP2P","params":[],"type":"PrivacyKey"},{"id":"894777186","predicate":"textAnchor","params":[{"name":"text","type":"RichText"},{"name":"name","type":"string"}],"type":"RichText"},{"id":"-1945767479","predicate":"help.supportName","params":[{"name":"name","type":"string"}],"type":"help.SupportName"},{"id":"-206688531","predicate":"help.userInfoEmpty","params":[],"type":"help.UserInfo"},{"id":"32192344","predicate":"help.userInfo","params":[{"name":"message","type":"string"},{"name":"entities","type":"Vector<MessageEntity>"},{"name":"author","type":"string"},{"name":"date","type":"int"}],"type":"help.UserInfo"},{"id":"-202219658","predicate":"messageActionContactSignUp","params":[],"type":"MessageAction"},{"id":"-1398708869","predicate":"updateMessagePoll","params":[{"name":"flags","type":"#"},{"name":"poll_id","type":"long"},{"name":"poll","type":"flags.0?Poll"},{"name":"results","type":"PollResults"}],"type":"Update"},{"id":"1823064809","predicate":"pollAnswer","params":[{"name":"text","type":"string"},{"name":"option","type":"bytes"}],"type":"PollAnswer"},{"id":"-716006138","predicate":"poll","params":[{"name":"id","type":"long"},{"name":"flags","type":"#"},{"name":"closed","type":"flags.0?true"},{"name":"question","type":"string"},{"name":"answers","type":"Vector<PollAnswer>"}],"type":"Poll"},{"id":"997055186","predicate":"pollAnswerVoters","params":[{"name":"flags","type":"#"},{"name":"chosen","type":"flags.0?true"},{"name":"option","type":"bytes"},{"name":"voters","type":"int"}],"type":"PollAnswerVoters"},{"id":"1465219162","predicate":"pollResults","params":[{"name":"flags","type":"#"},{"name":"min","type":"flags.0?true"},{"name":"results","type":"flags.1?Vector<PollAnswerVoters>"},{"name":"total_voters","type":"flags.2?int"}],"type":"PollResults"},{"id":"112424539","predicate":"inputMediaPoll","params":[{"name":"poll","type":"Poll"}],"type":"InputMedia"},{"id":"1272375192","predicate":"messageMediaPoll","params":[{"name":"poll","type":"Poll"},{"name":"results","type":"PollResults"}],"type":"MessageMedia"},{"id":"-264117680","predicate":"chatOnlines","params":[{"name":"onlines","type":"int"}],"type":"ChatOnlines"},{"id":"1202287072","predicate":"statsURL","params":[{"name":"url","type":"string"}],"type":"StatsURL"},{"id":"-525288402","predicate":"photoStrippedSize","params":[{"name":"type","type":"string"},{"name":"bytes","type":"bytes"}],"type":"PhotoSize"},{"id":"1605510357","predicate":"chatAdminRights","params":[{"name":"flags","type":"#"},{"name":"change_info","type":"flags.0?true"},{"name":"post_messages","type":"flags.1?true"},{"name":"edit_messages","type":"flags.2?true"},{"name":"delete_messages","type":"flags.3?true"},{"name":"ban_users","type":"flags.4?true"},{"name":"invite_users","type":"flags.5?true"},{"name":"pin_messages","type":"flags.7?true"},{"name":"add_admins","type":"flags.9?true"}],"type":"ChatAdminRights"},{"id":"-1626209256","predicate":"chatBannedRights","params":[{"name":"flags","type":"#"},{"name":"view_messages","type":"flags.0?true"},{"name":"send_messages","type":"flags.1?true"},{"name":"send_media","type":"flags.2?true"},{"name":"send_stickers","type":"flags.3?true"},{"name":"send_gifs","type":"flags.4?true"},{"name":"send_games","type":"flags.5?true"},{"name":"send_inline","type":"flags.6?true"},{"name":"embed_links","type":"flags.7?true"},{"name":"send_polls","type":"flags.8?true"},{"name":"change_info","type":"flags.10?true"},{"name":"invite_users","type":"flags.15?true"},{"name":"pin_messages","type":"flags.17?true"},{"name":"until_date","type":"int"}],"type":"ChatBannedRights"},{"id":"1421875280","predicate":"updateChatDefaultBannedRights","params":[{"name":"peer","type":"Peer"},{"name":"default_banned_rights","type":"ChatBannedRights"},{"name":"version","type":"int"}],"type":"Update"},{"id":"-433014407","predicate":"inputWallPaper","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputWallPaper"},{"id":"1913199744","predicate":"inputWallPaperSlug","params":[{"name":"slug","type":"string"}],"type":"InputWallPaper"},{"id":"-1150621555","predicate":"channelParticipantsContacts","params":[{"name":"q","type":"string"}],"type":"ChannelParticipantsFilter"},{"id":"771095562","predicate":"channelAdminLogEventActionDefaultBannedRights","params":[{"name":"prev_banned_rights","type":"ChatBannedRights"},{"name":"new_banned_rights","type":"ChatBannedRights"}],"type":"ChannelAdminLogEventAction"},{"id":"-1895328189","predicate":"channelAdminLogEventActionStopPoll","params":[{"name":"message","type":"Message"}],"type":"ChannelAdminLogEventAction"},{"id":"471437699","predicate":"account.wallPapersNotModified","params":[],"type":"account.WallPapers"},{"id":"1881892265","predicate":"account.wallPapers","params":[{"name":"hash","type":"int"},{"name":"wallpapers","type":"Vector<WallPaper>"}],"type":"account.WallPapers"},{"id":"-557924733","predicate":"codeSettings","params":[{"name":"flags","type":"#"},{"name":"allow_flashcall","type":"flags.0?true"},{"name":"current_number","type":"flags.1?true"},{"name":"allow_app_hash","type":"flags.4?true"}],"type":"CodeSettings"},{"id":"-1590738760","predicate":"wallPaperSettings","params":[{"name":"flags","type":"#"},{"name":"blur","type":"flags.1?true"},{"name":"motion","type":"flags.2?true"},{"name":"background_color","type":"flags.0?int"},{"name":"intensity","type":"flags.3?int"}],"type":"WallPaperSettings"},{"id":"-767099577","predicate":"autoDownloadSettings","params":[{"name":"flags","type":"#"},{"name":"disabled","type":"flags.0?true"},{"name":"video_preload_large","type":"flags.1?true"},{"name":"audio_preload_next","type":"flags.2?true"},{"name":"phonecalls_less_data","type":"flags.3?true"},{"name":"photo_size_max","type":"int"},{"name":"video_size_max","type":"int"},{"name":"file_size_max","type":"int"}],"type":"AutoDownloadSettings"},{"id":"1674235686","predicate":"account.autoDownloadSettings","params":[{"name":"low","type":"AutoDownloadSettings"},{"name":"medium","type":"AutoDownloadSettings"},{"name":"high","type":"AutoDownloadSettings"}],"type":"account.AutoDownloadSettings"},{"id":"-709641735","predicate":"emojiKeyword","params":[{"name":"keyword","type":"string"},{"name":"emoticons","type":"Vector<string>"}],"type":"EmojiKeyword"},{"id":"594408994","predicate":"emojiKeywordDeleted","params":[{"name":"keyword","type":"string"},{"name":"emoticons","type":"Vector<string>"}],"type":"EmojiKeyword"},{"id":"1556570557","predicate":"emojiKeywordsDifference","params":[{"name":"lang_code","type":"string"},{"name":"from_version","type":"int"},{"name":"version","type":"int"},{"name":"keywords","type":"Vector<EmojiKeyword>"}],"type":"EmojiKeywordsDifference"},{"id":"-1519029347","predicate":"emojiURL","params":[{"name":"url","type":"string"}],"type":"EmojiURL"},{"id":"-1275374751","predicate":"emojiLanguage","params":[{"name":"lang_code","type":"string"}],"type":"EmojiLanguage"},{"id":"-1529000952","predicate":"inputPrivacyKeyForwards","params":[],"type":"InputPrivacyKey"},{"id":"1777096355","predicate":"privacyKeyForwards","params":[],"type":"PrivacyKey"},{"id":"1461304012","predicate":"inputPrivacyKeyProfilePhoto","params":[],"type":"InputPrivacyKey"},{"id":"-1777000467","predicate":"privacyKeyProfilePhoto","params":[],"type":"PrivacyKey"},{"id":"-1132476723","predicate":"fileLocationToBeDeprecated","params":[{"name":"volume_id","type":"long"},{"name":"local_id","type":"int"}],"type":"FileLocation"},{"id":"1075322878","predicate":"inputPhotoFileLocation","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"},{"name":"thumb_size","type":"string"}],"type":"InputFileLocation"},{"id":"-667654413","predicate":"inputPhotoLegacyFileLocation","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"file_reference","type":"bytes"},{"name":"volume_id","type":"long"},{"name":"local_id","type":"int"},{"name":"secret","type":"long"}],"type":"InputFileLocation"},{"id":"668375447","predicate":"inputPeerPhotoFileLocation","params":[{"name":"flags","type":"#"},{"name":"big","type":"flags.0?true"},{"name":"peer","type":"InputPeer"},{"name":"volume_id","type":"long"},{"name":"local_id","type":"int"}],"type":"InputFileLocation"},{"id":"230353641","predicate":"inputStickerSetThumb","params":[{"name":"stickerset","type":"InputStickerSet"},{"name":"volume_id","type":"long"},{"name":"local_id","type":"int"}],"type":"InputFileLocation"},{"id":"-11252123","predicate":"folder","params":[{"name":"flags","type":"#"},{"name":"autofill_new_broadcasts","type":"flags.0?true"},{"name":"autofill_public_groups","type":"flags.1?true"},{"name":"autofill_new_correspondents","type":"flags.2?true"},{"name":"id","type":"int"},{"name":"title","type":"string"},{"name":"photo","type":"flags.3?ChatPhoto"}],"type":"Folder"},{"id":"1908216652","predicate":"dialogFolder","params":[{"name":"flags","type":"#"},{"name":"pinned","type":"flags.2?true"},{"name":"folder","type":"Folder"},{"name":"peer","type":"Peer"},{"name":"top_message","type":"int"},{"name":"unread_muted_peers_count","type":"int"},{"name":"unread_unmuted_peers_count","type":"int"},{"name":"unread_muted_messages_count","type":"int"},{"name":"unread_unmuted_messages_count","type":"int"}],"type":"Dialog"},{"id":"1684014375","predicate":"inputDialogPeerFolder","params":[{"name":"folder_id","type":"int"}],"type":"InputDialogPeer"},{"id":"1363483106","predicate":"dialogPeerFolder","params":[{"name":"folder_id","type":"int"}],"type":"DialogPeer"},{"id":"-70073706","predicate":"inputFolderPeer","params":[{"name":"peer","type":"InputPeer"},{"name":"folder_id","type":"int"}],"type":"InputFolderPeer"},{"id":"-373643672","predicate":"folderPeer","params":[{"name":"peer","type":"Peer"},{"name":"folder_id","type":"int"}],"type":"FolderPeer"},{"id":"422972864","predicate":"updateFolderPeers","params":[{"name":"folder_peers","type":"Vector<FolderPeer>"},{"name":"pts","type":"int"},{"name":"pts_count","type":"int"}],"type":"Update"},{"id":"756118935","predicate":"inputUserFromMessage","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"user_id","type":"int"}],"type":"InputUser"},{"id":"707290417","predicate":"inputChannelFromMessage","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"channel_id","type":"int"}],"type":"InputChannel"},{"id":"398123750","predicate":"inputPeerUserFromMessage","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"user_id","type":"int"}],"type":"InputPeer"},{"id":"-1667893317","predicate":"inputPeerChannelFromMessage","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"channel_id","type":"int"}],"type":"InputPeer"},{"id":"55761658","predicate":"inputPrivacyKeyPhoneNumber","params":[],"type":"InputPrivacyKey"},{"id":"-778378131","predicate":"privacyKeyPhoneNumber","params":[],"type":"PrivacyKey"},{"id":"-1472172887","predicate":"topPeerCategoryForwardUsers","params":[],"type":"TopPeerCategory"},{"id":"-68239120","predicate":"topPeerCategoryForwardChats","params":[],"type":"TopPeerCategory"},{"id":"-1569748965","predicate":"channelAdminLogEventActionChangeLinkedChat","params":[{"name":"prev_value","type":"int"},{"name":"new_value","type":"int"}],"type":"ChannelAdminLogEventAction"},{"id":"-398136321","predicate":"messages.searchCounter","params":[{"name":"flags","type":"#"},{"name":"inexact","type":"flags.1?true"},{"name":"filter","type":"MessagesFilter"},{"name":"count","type":"int"}],"type":"messages.SearchCounter"},{"id":"280464681","predicate":"keyboardButtonUrlAuth","params":[{"name":"flags","type":"#"},{"name":"text","type":"string"},{"name":"fwd_text","type":"flags.0?string"},{"name":"url","type":"string"},{"name":"button_id","type":"int"}],"type":"KeyboardButton"},{"id":"-802258988","predicate":"inputKeyboardButtonUrlAuth","params":[{"name":"flags","type":"#"},{"name":"request_write_access","type":"flags.0?true"},{"name":"text","type":"string"},{"name":"fwd_text","type":"flags.1?string"},{"name":"url","type":"string"},{"name":"bot","type":"InputUser"}],"type":"KeyboardButton"},{"id":"-1831650802","predicate":"urlAuthResultRequest","params":[{"name":"flags","type":"#"},{"name":"request_write_access","type":"flags.0?true"},{"name":"bot","type":"User"},{"name":"domain","type":"string"}],"type":"UrlAuthResult"},{"id":"-1886646706","predicate":"urlAuthResultAccepted","params":[{"name":"url","type":"string"}],"type":"UrlAuthResult"},{"id":"-1445536993","predicate":"urlAuthResultDefault","params":[],"type":"UrlAuthResult"},{"id":"1283572154","predicate":"inputPrivacyValueAllowChatParticipants","params":[{"name":"chats","type":"Vector<int>"}],"type":"InputPrivacyRule"},{"id":"-668769361","predicate":"inputPrivacyValueDisallowChatParticipants","params":[{"name":"chats","type":"Vector<int>"}],"type":"InputPrivacyRule"},{"id":"415136107","predicate":"privacyValueAllowChatParticipants","params":[{"name":"chats","type":"Vector<int>"}],"type":"PrivacyRule"},{"id":"-1397881200","predicate":"privacyValueDisallowChatParticipants","params":[{"name":"chats","type":"Vector<int>"}],"type":"PrivacyRule"},{"id":"-1672577397","predicate":"messageEntityUnderline","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"-1090087980","predicate":"messageEntityStrike","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"34469328","predicate":"messageEntityBlockquote","params":[{"name":"offset","type":"int"},{"name":"length","type":"int"}],"type":"MessageEntity"},{"id":"1786671974","predicate":"updatePeerSettings","params":[{"name":"peer","type":"Peer"},{"name":"settings","type":"PeerSettings"}],"type":"Update"},{"id":"-1078612597","predicate":"channelLocationEmpty","params":[],"type":"ChannelLocation"},{"id":"547062491","predicate":"channelLocation","params":[{"name":"geo_point","type":"GeoPoint"},{"name":"address","type":"string"}],"type":"ChannelLocation"},{"id":"-901375139","predicate":"peerLocated","params":[{"name":"peer","type":"Peer"},{"name":"expires","type":"int"},{"name":"distance","type":"int"}],"type":"PeerLocated"},{"id":"-1263546448","predicate":"updatePeerLocated","params":[{"name":"peers","type":"Vector<PeerLocated>"}],"type":"Update"},{"id":"241923758","predicate":"channelAdminLogEventActionChangeLocation","params":[{"name":"prev_value","type":"ChannelLocation"},{"name":"new_value","type":"ChannelLocation"}],"type":"ChannelAdminLogEventAction"},{"id":"-606798099","predicate":"inputReportReasonGeoIrrelevant","params":[],"type":"ReportReason"},{"id":"1401984889","predicate":"channelAdminLogEventActionToggleSlowMode","params":[{"name":"prev_value","type":"int"},{"name":"new_value","type":"int"}],"type":"ChannelAdminLogEventAction"},{"id":"1148485274","predicate":"auth.authorizationSignUpRequired","params":[{"name":"flags","type":"#"},{"name":"terms_of_service","type":"flags.0?help.TermsOfService"}],"type":"auth.Authorization"},{"id":"-666824391","predicate":"payments.paymentVerificationNeeded","params":[{"name":"url","type":"string"}],"type":"payments.PaymentResult"},{"id":"42402760","predicate":"inputStickerSetAnimatedEmoji","params":[],"type":"InputStickerSet"},{"id":"967122427","predicate":"updateNewScheduledMessage","params":[{"name":"message","type":"Message"}],"type":"Update"},{"id":"-1870238482","predicate":"updateDeleteScheduledMessages","params":[{"name":"peer","type":"Peer"},{"name":"messages","type":"Vector<int>"}],"type":"Update"},{"id":"-797791052","predicate":"restrictionReason","params":[{"name":"platform","type":"string"},{"name":"reason","type":"string"},{"name":"text","type":"string"}],"type":"RestrictionReason"},{"id":"1012306921","predicate":"inputTheme","params":[{"name":"id","type":"long"},{"name":"access_hash","type":"long"}],"type":"InputTheme"},{"id":"-175567375","predicate":"inputThemeSlug","params":[{"name":"slug","type":"string"}],"type":"InputTheme"},{"id":"1211967244","predicate":"themeDocumentNotModified","params":[],"type":"Theme"},{"id":"-136770336","predicate":"theme","params":[{"name":"flags","type":"#"},{"name":"creator","type":"flags.0?true"},{"name":"default","type":"flags.1?true"},{"name":"id","type":"long"},{"name":"access_hash","type":"long"},{"name":"slug","type":"string"},{"name":"title","type":"string"},{"name":"document","type":"flags.2?Document"},{"name":"installs_count","type":"int"}],"type":"Theme"},{"id":"-199313886","predicate":"account.themesNotModified","params":[],"type":"account.Themes"},{"id":"2137482273","predicate":"account.themes","params":[{"name":"hash","type":"int"},{"name":"themes","type":"Vector<Theme>"}],"type":"account.Themes"},{"id":"-2112423005","predicate":"updateTheme","params":[{"name":"theme","type":"Theme"}],"type":"Update"},{"id":"-786326563","predicate":"inputPrivacyKeyAddedByPhone","params":[],"type":"InputPrivacyKey"},{"id":"1124062251","predicate":"privacyKeyAddedByPhone","params":[],"type":"PrivacyKey"}],"methods":[{"id":"-878758099","method":"invokeAfterMsg","params":[{"name":"msg_id","type":"long"},{"name":"query","type":"!X"}],"type":"X"},{"id":"1036301552","method":"invokeAfterMsgs","params":[{"name":"msg_ids","type":"Vector<long>"},{"name":"query","type":"!X"}],"type":"X"},{"id":"-1502141361","method":"auth.sendCode","params":[{"name":"phone_number","type":"string"},{"name":"api_id","type":"int"},{"name":"api_hash","type":"string"},{"name":"settings","type":"CodeSettings"}],"type":"auth.SentCode"},{"id":"-2131827673","method":"auth.signUp","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"}],"type":"auth.Authorization"},{"id":"-1126886015","method":"auth.signIn","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"},{"name":"phone_code","type":"string"}],"type":"auth.Authorization"},{"id":"1461180992","method":"auth.logOut","params":[],"type":"Bool"},{"id":"-1616179942","method":"auth.resetAuthorizations","params":[],"type":"Bool"},{"id":"-440401971","method":"auth.exportAuthorization","params":[{"name":"dc_id","type":"int"}],"type":"auth.ExportedAuthorization"},{"id":"-470837741","method":"auth.importAuthorization","params":[{"name":"id","type":"int"},{"name":"bytes","type":"bytes"}],"type":"auth.Authorization"},{"id":"-841733627","method":"auth.bindTempAuthKey","params":[{"name":"perm_auth_key_id","type":"long"},{"name":"nonce","type":"long"},{"name":"expires_at","type":"int"},{"name":"encrypted_message","type":"bytes"}],"type":"Bool"},{"id":"1754754159","method":"account.registerDevice","params":[{"name":"flags","type":"#"},{"name":"no_muted","type":"flags.0?true"},{"name":"token_type","type":"int"},{"name":"token","type":"string"},{"name":"app_sandbox","type":"Bool"},{"name":"secret","type":"bytes"},{"name":"other_uids","type":"Vector<int>"}],"type":"Bool"},{"id":"813089983","method":"account.unregisterDevice","params":[{"name":"token_type","type":"int"},{"name":"token","type":"string"},{"name":"other_uids","type":"Vector<int>"}],"type":"Bool"},{"id":"-2067899501","method":"account.updateNotifySettings","params":[{"name":"peer","type":"InputNotifyPeer"},{"name":"settings","type":"InputPeerNotifySettings"}],"type":"Bool"},{"id":"313765169","method":"account.getNotifySettings","params":[{"name":"peer","type":"InputNotifyPeer"}],"type":"PeerNotifySettings"},{"id":"-612493497","method":"account.resetNotifySettings","params":[],"type":"Bool"},{"id":"2018596725","method":"account.updateProfile","params":[{"name":"flags","type":"#"},{"name":"first_name","type":"flags.0?string"},{"name":"last_name","type":"flags.1?string"},{"name":"about","type":"flags.2?string"}],"type":"User"},{"id":"1713919532","method":"account.updateStatus","params":[{"name":"offline","type":"Bool"}],"type":"Bool"},{"id":"-1430579357","method":"account.getWallPapers","params":[{"name":"hash","type":"int"}],"type":"account.WallPapers"},{"id":"-1374118561","method":"account.reportPeer","params":[{"name":"peer","type":"InputPeer"},{"name":"reason","type":"ReportReason"}],"type":"Bool"},{"id":"227648840","method":"users.getUsers","params":[{"name":"id","type":"Vector<InputUser>"}],"type":"Vector<User>"},{"id":"-902781519","method":"users.getFullUser","params":[{"name":"id","type":"InputUser"}],"type":"UserFull"},{"id":"749357634","method":"contacts.getContactIDs","params":[{"name":"hash","type":"int"}],"type":"Vector<int>"},{"id":"-995929106","method":"contacts.getStatuses","params":[],"type":"Vector<ContactStatus>"},{"id":"-1071414113","method":"contacts.getContacts","params":[{"name":"hash","type":"int"}],"type":"contacts.Contacts"},{"id":"746589157","method":"contacts.importContacts","params":[{"name":"contacts","type":"Vector<InputContact>"}],"type":"contacts.ImportedContacts"},{"id":"157945344","method":"contacts.deleteContacts","params":[{"name":"id","type":"Vector<InputUser>"}],"type":"Updates"},{"id":"269745566","method":"contacts.deleteByPhones","params":[{"name":"phones","type":"Vector<string>"}],"type":"Bool"},{"id":"858475004","method":"contacts.block","params":[{"name":"id","type":"InputUser"}],"type":"Bool"},{"id":"-448724803","method":"contacts.unblock","params":[{"name":"id","type":"InputUser"}],"type":"Bool"},{"id":"-176409329","method":"contacts.getBlocked","params":[{"name":"offset","type":"int"},{"name":"limit","type":"int"}],"type":"contacts.Blocked"},{"id":"1673946374","method":"messages.getMessages","params":[{"name":"id","type":"Vector<InputMessage>"}],"type":"messages.Messages"},{"id":"-1594999949","method":"messages.getDialogs","params":[{"name":"flags","type":"#"},{"name":"exclude_pinned","type":"flags.0?true"},{"name":"folder_id","type":"flags.1?int"},{"name":"offset_date","type":"int"},{"name":"offset_id","type":"int"},{"name":"offset_peer","type":"InputPeer"},{"name":"limit","type":"int"},{"name":"hash","type":"int"}],"type":"messages.Dialogs"},{"id":"-591691168","method":"messages.getHistory","params":[{"name":"peer","type":"InputPeer"},{"name":"offset_id","type":"int"},{"name":"offset_date","type":"int"},{"name":"add_offset","type":"int"},{"name":"limit","type":"int"},{"name":"max_id","type":"int"},{"name":"min_id","type":"int"},{"name":"hash","type":"int"}],"type":"messages.Messages"},{"id":"-2045448344","method":"messages.search","params":[{"name":"flags","type":"#"},{"name":"peer","type":"InputPeer"},{"name":"q","type":"string"},{"name":"from_id","type":"flags.0?InputUser"},{"name":"filter","type":"MessagesFilter"},{"name":"min_date","type":"int"},{"name":"max_date","type":"int"},{"name":"offset_id","type":"int"},{"name":"add_offset","type":"int"},{"name":"limit","type":"int"},{"name":"max_id","type":"int"},{"name":"min_id","type":"int"},{"name":"hash","type":"int"}],"type":"messages.Messages"},{"id":"238054714","method":"messages.readHistory","params":[{"name":"peer","type":"InputPeer"},{"name":"max_id","type":"int"}],"type":"messages.AffectedMessages"},{"id":"469850889","method":"messages.deleteHistory","params":[{"name":"flags","type":"#"},{"name":"just_clear","type":"flags.0?true"},{"name":"revoke","type":"flags.1?true"},{"name":"peer","type":"InputPeer"},{"name":"max_id","type":"int"}],"type":"messages.AffectedHistory"},{"id":"-443640366","method":"messages.deleteMessages","params":[{"name":"flags","type":"#"},{"name":"revoke","type":"flags.0?true"},{"name":"id","type":"Vector<int>"}],"type":"messages.AffectedMessages"},{"id":"94983360","method":"messages.receivedMessages","params":[{"name":"max_id","type":"int"}],"type":"Vector<ReceivedNotifyMessage>"},{"id":"-1551737264","method":"messages.setTyping","params":[{"name":"peer","type":"InputPeer"},{"name":"action","type":"SendMessageAction"}],"type":"Bool"},{"id":"1376532592","method":"messages.sendMessage","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.1?true"},{"name":"silent","type":"flags.5?true"},{"name":"background","type":"flags.6?true"},{"name":"clear_draft","type":"flags.7?true"},{"name":"peer","type":"InputPeer"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"message","type":"string"},{"name":"random_id","type":"long"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"},{"name":"schedule_date","type":"flags.10?int"}],"type":"Updates"},{"id":"881978281","method":"messages.sendMedia","params":[{"name":"flags","type":"#"},{"name":"silent","type":"flags.5?true"},{"name":"background","type":"flags.6?true"},{"name":"clear_draft","type":"flags.7?true"},{"name":"peer","type":"InputPeer"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"media","type":"InputMedia"},{"name":"message","type":"string"},{"name":"random_id","type":"long"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"},{"name":"schedule_date","type":"flags.10?int"}],"type":"Updates"},{"id":"-637606386","method":"messages.forwardMessages","params":[{"name":"flags","type":"#"},{"name":"silent","type":"flags.5?true"},{"name":"background","type":"flags.6?true"},{"name":"with_my_score","type":"flags.8?true"},{"name":"grouped","type":"flags.9?true"},{"name":"from_peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"},{"name":"random_id","type":"Vector<long>"},{"name":"to_peer","type":"InputPeer"},{"name":"schedule_date","type":"flags.10?int"}],"type":"Updates"},{"id":"-820669733","method":"messages.reportSpam","params":[{"name":"peer","type":"InputPeer"}],"type":"Bool"},{"id":"913498268","method":"messages.getPeerSettings","params":[{"name":"peer","type":"InputPeer"}],"type":"PeerSettings"},{"id":"-1115507112","method":"messages.report","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"},{"name":"reason","type":"ReportReason"}],"type":"Bool"},{"id":"1013621127","method":"messages.getChats","params":[{"name":"id","type":"Vector<int>"}],"type":"messages.Chats"},{"id":"998448230","method":"messages.getFullChat","params":[{"name":"chat_id","type":"int"}],"type":"messages.ChatFull"},{"id":"-599447467","method":"messages.editChatTitle","params":[{"name":"chat_id","type":"int"},{"name":"title","type":"string"}],"type":"Updates"},{"id":"-900957736","method":"messages.editChatPhoto","params":[{"name":"chat_id","type":"int"},{"name":"photo","type":"InputChatPhoto"}],"type":"Updates"},{"id":"-106911223","method":"messages.addChatUser","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"InputUser"},{"name":"fwd_limit","type":"int"}],"type":"Updates"},{"id":"-530505962","method":"messages.deleteChatUser","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"InputUser"}],"type":"Updates"},{"id":"164303470","method":"messages.createChat","params":[{"name":"users","type":"Vector<InputUser>"},{"name":"title","type":"string"}],"type":"Updates"},{"id":"-304838614","method":"updates.getState","params":[],"type":"updates.State"},{"id":"630429265","method":"updates.getDifference","params":[{"name":"flags","type":"#"},{"name":"pts","type":"int"},{"name":"pts_total_limit","type":"flags.0?int"},{"name":"date","type":"int"},{"name":"qts","type":"int"}],"type":"updates.Difference"},{"id":"-256159406","method":"photos.updateProfilePhoto","params":[{"name":"id","type":"InputPhoto"}],"type":"UserProfilePhoto"},{"id":"1328726168","method":"photos.uploadProfilePhoto","params":[{"name":"file","type":"InputFile"}],"type":"photos.Photo"},{"id":"-2016444625","method":"photos.deletePhotos","params":[{"name":"id","type":"Vector<InputPhoto>"}],"type":"Vector<long>"},{"id":"-1291540959","method":"upload.saveFilePart","params":[{"name":"file_id","type":"long"},{"name":"file_part","type":"int"},{"name":"bytes","type":"bytes"}],"type":"Bool"},{"id":"-1319462148","method":"upload.getFile","params":[{"name":"flags","type":"#"},{"name":"precise","type":"flags.0?true"},{"name":"location","type":"InputFileLocation"},{"name":"offset","type":"int"},{"name":"limit","type":"int"}],"type":"upload.File"},{"id":"-990308245","method":"help.getConfig","params":[],"type":"Config"},{"id":"531836966","method":"help.getNearestDc","params":[],"type":"NearestDc"},{"id":"1378703997","method":"help.getAppUpdate","params":[{"name":"source","type":"string"}],"type":"help.AppUpdate"},{"id":"1295590211","method":"help.getInviteText","params":[],"type":"help.InviteText"},{"id":"-1848823128","method":"photos.getUserPhotos","params":[{"name":"user_id","type":"InputUser"},{"name":"offset","type":"int"},{"name":"max_id","type":"long"},{"name":"limit","type":"int"}],"type":"photos.Photos"},{"id":"651135312","method":"messages.getDhConfig","params":[{"name":"version","type":"int"},{"name":"random_length","type":"int"}],"type":"messages.DhConfig"},{"id":"-162681021","method":"messages.requestEncryption","params":[{"name":"user_id","type":"InputUser"},{"name":"random_id","type":"int"},{"name":"g_a","type":"bytes"}],"type":"EncryptedChat"},{"id":"1035731989","method":"messages.acceptEncryption","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"g_b","type":"bytes"},{"name":"key_fingerprint","type":"long"}],"type":"EncryptedChat"},{"id":"-304536635","method":"messages.discardEncryption","params":[{"name":"chat_id","type":"int"}],"type":"Bool"},{"id":"2031374829","method":"messages.setEncryptedTyping","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"typing","type":"Bool"}],"type":"Bool"},{"id":"2135648522","method":"messages.readEncryptedHistory","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"max_date","type":"int"}],"type":"Bool"},{"id":"-1451792525","method":"messages.sendEncrypted","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"random_id","type":"long"},{"name":"data","type":"bytes"}],"type":"messages.SentEncryptedMessage"},{"id":"-1701831834","method":"messages.sendEncryptedFile","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"random_id","type":"long"},{"name":"data","type":"bytes"},{"name":"file","type":"InputEncryptedFile"}],"type":"messages.SentEncryptedMessage"},{"id":"852769188","method":"messages.sendEncryptedService","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"random_id","type":"long"},{"name":"data","type":"bytes"}],"type":"messages.SentEncryptedMessage"},{"id":"1436924774","method":"messages.receivedQueue","params":[{"name":"max_qts","type":"int"}],"type":"Vector<long>"},{"id":"1259113487","method":"messages.reportEncryptedSpam","params":[{"name":"peer","type":"InputEncryptedChat"}],"type":"Bool"},{"id":"-562337987","method":"upload.saveBigFilePart","params":[{"name":"file_id","type":"long"},{"name":"file_part","type":"int"},{"name":"file_total_parts","type":"int"},{"name":"bytes","type":"bytes"}],"type":"Bool"},{"id":"2018609336","method":"initConnection","params":[{"name":"flags","type":"#"},{"name":"api_id","type":"int"},{"name":"device_model","type":"string"},{"name":"system_version","type":"string"},{"name":"app_version","type":"string"},{"name":"system_lang_code","type":"string"},{"name":"lang_pack","type":"string"},{"name":"lang_code","type":"string"},{"name":"proxy","type":"flags.0?InputClientProxy"},{"name":"query","type":"!X"}],"type":"X"},{"id":"-1663104819","method":"help.getSupport","params":[],"type":"help.Support"},{"id":"916930423","method":"messages.readMessageContents","params":[{"name":"id","type":"Vector<int>"}],"type":"messages.AffectedMessages"},{"id":"655677548","method":"account.checkUsername","params":[{"name":"username","type":"string"}],"type":"Bool"},{"id":"1040964988","method":"account.updateUsername","params":[{"name":"username","type":"string"}],"type":"User"},{"id":"301470424","method":"contacts.search","params":[{"name":"q","type":"string"},{"name":"limit","type":"int"}],"type":"contacts.Found"},{"id":"-623130288","method":"account.getPrivacy","params":[{"name":"key","type":"InputPrivacyKey"}],"type":"account.PrivacyRules"},{"id":"-906486552","method":"account.setPrivacy","params":[{"name":"key","type":"InputPrivacyKey"},{"name":"rules","type":"Vector<InputPrivacyRule>"}],"type":"account.PrivacyRules"},{"id":"1099779595","method":"account.deleteAccount","params":[{"name":"reason","type":"string"}],"type":"Bool"},{"id":"150761757","method":"account.getAccountTTL","params":[],"type":"AccountDaysTTL"},{"id":"608323678","method":"account.setAccountTTL","params":[{"name":"ttl","type":"AccountDaysTTL"}],"type":"Bool"},{"id":"-627372787","method":"invokeWithLayer","params":[{"name":"layer","type":"int"},{"name":"query","type":"!X"}],"type":"X"},{"id":"-113456221","method":"contacts.resolveUsername","params":[{"name":"username","type":"string"}],"type":"contacts.ResolvedPeer"},{"id":"-2108208411","method":"account.sendChangePhoneCode","params":[{"name":"phone_number","type":"string"},{"name":"settings","type":"CodeSettings"}],"type":"auth.SentCode"},{"id":"1891839707","method":"account.changePhone","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"},{"name":"phone_code","type":"string"}],"type":"User"},{"id":"71126828","method":"messages.getStickers","params":[{"name":"emoticon","type":"string"},{"name":"hash","type":"int"}],"type":"messages.Stickers"},{"id":"479598769","method":"messages.getAllStickers","params":[{"name":"hash","type":"int"}],"type":"messages.AllStickers"},{"id":"954152242","method":"account.updateDeviceLocked","params":[{"name":"period","type":"int"}],"type":"Bool"},{"id":"1738800940","method":"auth.importBotAuthorization","params":[{"name":"flags","type":"int"},{"name":"api_id","type":"int"},{"name":"api_hash","type":"string"},{"name":"bot_auth_token","type":"string"}],"type":"auth.Authorization"},{"id":"-1956073268","method":"messages.getWebPagePreview","params":[{"name":"flags","type":"#"},{"name":"message","type":"string"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"}],"type":"MessageMedia"},{"id":"-484392616","method":"account.getAuthorizations","params":[],"type":"account.Authorizations"},{"id":"-545786948","method":"account.resetAuthorization","params":[{"name":"hash","type":"long"}],"type":"Bool"},{"id":"1418342645","method":"account.getPassword","params":[],"type":"account.Password"},{"id":"-1663767815","method":"account.getPasswordSettings","params":[{"name":"password","type":"InputCheckPasswordSRP"}],"type":"account.PasswordSettings"},{"id":"-1516564433","method":"account.updatePasswordSettings","params":[{"name":"password","type":"InputCheckPasswordSRP"},{"name":"new_settings","type":"account.PasswordInputSettings"}],"type":"Bool"},{"id":"-779399914","method":"auth.checkPassword","params":[{"name":"password","type":"InputCheckPasswordSRP"}],"type":"auth.Authorization"},{"id":"-661144474","method":"auth.requestPasswordRecovery","params":[],"type":"auth.PasswordRecovery"},{"id":"1319464594","method":"auth.recoverPassword","params":[{"name":"code","type":"string"}],"type":"auth.Authorization"},{"id":"-1080796745","method":"invokeWithoutUpdates","params":[{"name":"query","type":"!X"}],"type":"X"},{"id":"234312524","method":"messages.exportChatInvite","params":[{"name":"peer","type":"InputPeer"}],"type":"ExportedChatInvite"},{"id":"1051570619","method":"messages.checkChatInvite","params":[{"name":"hash","type":"string"}],"type":"ChatInvite"},{"id":"1817183516","method":"messages.importChatInvite","params":[{"name":"hash","type":"string"}],"type":"Updates"},{"id":"639215886","method":"messages.getStickerSet","params":[{"name":"stickerset","type":"InputStickerSet"}],"type":"messages.StickerSet"},{"id":"-946871200","method":"messages.installStickerSet","params":[{"name":"stickerset","type":"InputStickerSet"},{"name":"archived","type":"Bool"}],"type":"messages.StickerSetInstallResult"},{"id":"-110209570","method":"messages.uninstallStickerSet","params":[{"name":"stickerset","type":"InputStickerSet"}],"type":"Bool"},{"id":"-421563528","method":"messages.startBot","params":[{"name":"bot","type":"InputUser"},{"name":"peer","type":"InputPeer"},{"name":"random_id","type":"long"},{"name":"start_param","type":"string"}],"type":"Updates"},{"id":"-1877938321","method":"help.getAppChangelog","params":[{"name":"prev_app_version","type":"string"}],"type":"Updates"},{"id":"-993483427","method":"messages.getMessagesViews","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"},{"name":"increment","type":"Bool"}],"type":"Vector<int>"},{"id":"-871347913","method":"channels.readHistory","params":[{"name":"channel","type":"InputChannel"},{"name":"max_id","type":"int"}],"type":"Bool"},{"id":"-2067661490","method":"channels.deleteMessages","params":[{"name":"channel","type":"InputChannel"},{"name":"id","type":"Vector<int>"}],"type":"messages.AffectedMessages"},{"id":"-787622117","method":"channels.deleteUserHistory","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"}],"type":"messages.AffectedHistory"},{"id":"-32999408","method":"channels.reportSpam","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"},{"name":"id","type":"Vector<int>"}],"type":"Bool"},{"id":"-1383294429","method":"channels.getMessages","params":[{"name":"channel","type":"InputChannel"},{"name":"id","type":"Vector<InputMessage>"}],"type":"messages.Messages"},{"id":"306054633","method":"channels.getParticipants","params":[{"name":"channel","type":"InputChannel"},{"name":"filter","type":"ChannelParticipantsFilter"},{"name":"offset","type":"int"},{"name":"limit","type":"int"},{"name":"hash","type":"int"}],"type":"channels.ChannelParticipants"},{"id":"1416484774","method":"channels.getParticipant","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"}],"type":"channels.ChannelParticipant"},{"id":"176122811","method":"channels.getChannels","params":[{"name":"id","type":"Vector<InputChannel>"}],"type":"messages.Chats"},{"id":"141781513","method":"channels.getFullChannel","params":[{"name":"channel","type":"InputChannel"}],"type":"messages.ChatFull"},{"id":"1029681423","method":"channels.createChannel","params":[{"name":"flags","type":"#"},{"name":"broadcast","type":"flags.0?true"},{"name":"megagroup","type":"flags.1?true"},{"name":"title","type":"string"},{"name":"about","type":"string"},{"name":"geo_point","type":"flags.2?InputGeoPoint"},{"name":"address","type":"flags.2?string"}],"type":"Updates"},{"id":"-751007486","method":"channels.editAdmin","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"},{"name":"admin_rights","type":"ChatAdminRights"},{"name":"rank","type":"string"}],"type":"Updates"},{"id":"1450044624","method":"channels.editTitle","params":[{"name":"channel","type":"InputChannel"},{"name":"title","type":"string"}],"type":"Updates"},{"id":"-248621111","method":"channels.editPhoto","params":[{"name":"channel","type":"InputChannel"},{"name":"photo","type":"InputChatPhoto"}],"type":"Updates"},{"id":"283557164","method":"channels.checkUsername","params":[{"name":"channel","type":"InputChannel"},{"name":"username","type":"string"}],"type":"Bool"},{"id":"890549214","method":"channels.updateUsername","params":[{"name":"channel","type":"InputChannel"},{"name":"username","type":"string"}],"type":"Bool"},{"id":"615851205","method":"channels.joinChannel","params":[{"name":"channel","type":"InputChannel"}],"type":"Updates"},{"id":"-130635115","method":"channels.leaveChannel","params":[{"name":"channel","type":"InputChannel"}],"type":"Updates"},{"id":"429865580","method":"channels.inviteToChannel","params":[{"name":"channel","type":"InputChannel"},{"name":"users","type":"Vector<InputUser>"}],"type":"Updates"},{"id":"-1072619549","method":"channels.deleteChannel","params":[{"name":"channel","type":"InputChannel"}],"type":"Updates"},{"id":"51854712","method":"updates.getChannelDifference","params":[{"name":"flags","type":"#"},{"name":"force","type":"flags.0?true"},{"name":"channel","type":"InputChannel"},{"name":"filter","type":"ChannelMessagesFilter"},{"name":"pts","type":"int"},{"name":"limit","type":"int"}],"type":"updates.ChannelDifference"},{"id":"-1444503762","method":"messages.editChatAdmin","params":[{"name":"chat_id","type":"int"},{"name":"user_id","type":"InputUser"},{"name":"is_admin","type":"Bool"}],"type":"Bool"},{"id":"363051235","method":"messages.migrateChat","params":[{"name":"chat_id","type":"int"}],"type":"Updates"},{"id":"-1083038300","method":"messages.searchGlobal","params":[{"name":"flags","type":"#"},{"name":"folder_id","type":"flags.0?int"},{"name":"q","type":"string"},{"name":"offset_rate","type":"int"},{"name":"offset_peer","type":"InputPeer"},{"name":"offset_id","type":"int"},{"name":"limit","type":"int"}],"type":"messages.Messages"},{"id":"2016638777","method":"messages.reorderStickerSets","params":[{"name":"flags","type":"#"},{"name":"masks","type":"flags.0?true"},{"name":"order","type":"Vector<long>"}],"type":"Bool"},{"id":"864953444","method":"messages.getDocumentByHash","params":[{"name":"sha256","type":"bytes"},{"name":"size","type":"int"},{"name":"mime_type","type":"string"}],"type":"Document"},{"id":"-1080395925","method":"messages.searchGifs","params":[{"name":"q","type":"string"},{"name":"offset","type":"int"}],"type":"messages.FoundGifs"},{"id":"-2084618926","method":"messages.getSavedGifs","params":[{"name":"hash","type":"int"}],"type":"messages.SavedGifs"},{"id":"846868683","method":"messages.saveGif","params":[{"name":"id","type":"InputDocument"},{"name":"unsave","type":"Bool"}],"type":"Bool"},{"id":"1364105629","method":"messages.getInlineBotResults","params":[{"name":"flags","type":"#"},{"name":"bot","type":"InputUser"},{"name":"peer","type":"InputPeer"},{"name":"geo_point","type":"flags.0?InputGeoPoint"},{"name":"query","type":"string"},{"name":"offset","type":"string"}],"type":"messages.BotResults"},{"id":"-346119674","method":"messages.setInlineBotResults","params":[{"name":"flags","type":"#"},{"name":"gallery","type":"flags.0?true"},{"name":"private","type":"flags.1?true"},{"name":"query_id","type":"long"},{"name":"results","type":"Vector<InputBotInlineResult>"},{"name":"cache_time","type":"int"},{"name":"next_offset","type":"flags.2?string"},{"name":"switch_pm","type":"flags.3?InlineBotSwitchPM"}],"type":"Bool"},{"id":"570955184","method":"messages.sendInlineBotResult","params":[{"name":"flags","type":"#"},{"name":"silent","type":"flags.5?true"},{"name":"background","type":"flags.6?true"},{"name":"clear_draft","type":"flags.7?true"},{"name":"hide_via","type":"flags.11?true"},{"name":"peer","type":"InputPeer"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"random_id","type":"long"},{"name":"query_id","type":"long"},{"name":"id","type":"string"},{"name":"schedule_date","type":"flags.10?int"}],"type":"Updates"},{"id":"-826838685","method":"channels.exportMessageLink","params":[{"name":"channel","type":"InputChannel"},{"name":"id","type":"int"},{"name":"grouped","type":"Bool"}],"type":"ExportedMessageLink"},{"id":"527021574","method":"channels.toggleSignatures","params":[{"name":"channel","type":"InputChannel"},{"name":"enabled","type":"Bool"}],"type":"Updates"},{"id":"1056025023","method":"auth.resendCode","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"}],"type":"auth.SentCode"},{"id":"520357240","method":"auth.cancelCode","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"}],"type":"Bool"},{"id":"-39416522","method":"messages.getMessageEditData","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"int"}],"type":"messages.MessageEditData"},{"id":"1224152952","method":"messages.editMessage","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.1?true"},{"name":"peer","type":"InputPeer"},{"name":"id","type":"int"},{"name":"message","type":"flags.11?string"},{"name":"media","type":"flags.14?InputMedia"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"},{"name":"schedule_date","type":"flags.15?int"}],"type":"Updates"},{"id":"-2091549254","method":"messages.editInlineBotMessage","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.1?true"},{"name":"id","type":"InputBotInlineMessageID"},{"name":"message","type":"flags.11?string"},{"name":"media","type":"flags.14?InputMedia"},{"name":"reply_markup","type":"flags.2?ReplyMarkup"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"}],"type":"Bool"},{"id":"-2130010132","method":"messages.getBotCallbackAnswer","params":[{"name":"flags","type":"#"},{"name":"game","type":"flags.1?true"},{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"data","type":"flags.0?bytes"}],"type":"messages.BotCallbackAnswer"},{"id":"-712043766","method":"messages.setBotCallbackAnswer","params":[{"name":"flags","type":"#"},{"name":"alert","type":"flags.1?true"},{"name":"query_id","type":"long"},{"name":"message","type":"flags.0?string"},{"name":"url","type":"flags.2?string"},{"name":"cache_time","type":"int"}],"type":"Bool"},{"id":"-728224331","method":"contacts.getTopPeers","params":[{"name":"flags","type":"#"},{"name":"correspondents","type":"flags.0?true"},{"name":"bots_pm","type":"flags.1?true"},{"name":"bots_inline","type":"flags.2?true"},{"name":"phone_calls","type":"flags.3?true"},{"name":"forward_users","type":"flags.4?true"},{"name":"forward_chats","type":"flags.5?true"},{"name":"groups","type":"flags.10?true"},{"name":"channels","type":"flags.15?true"},{"name":"offset","type":"int"},{"name":"limit","type":"int"},{"name":"hash","type":"int"}],"type":"contacts.TopPeers"},{"id":"451113900","method":"contacts.resetTopPeerRating","params":[{"name":"category","type":"TopPeerCategory"},{"name":"peer","type":"InputPeer"}],"type":"Bool"},{"id":"-462373635","method":"messages.getPeerDialogs","params":[{"name":"peers","type":"Vector<InputDialogPeer>"}],"type":"messages.PeerDialogs"},{"id":"-1137057461","method":"messages.saveDraft","params":[{"name":"flags","type":"#"},{"name":"no_webpage","type":"flags.1?true"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"peer","type":"InputPeer"},{"name":"message","type":"string"},{"name":"entities","type":"flags.3?Vector<MessageEntity>"}],"type":"Bool"},{"id":"1782549861","method":"messages.getAllDrafts","params":[],"type":"Updates"},{"id":"766298703","method":"messages.getFeaturedStickers","params":[{"name":"hash","type":"int"}],"type":"messages.FeaturedStickers"},{"id":"1527873830","method":"messages.readFeaturedStickers","params":[{"name":"id","type":"Vector<long>"}],"type":"Bool"},{"id":"1587647177","method":"messages.getRecentStickers","params":[{"name":"flags","type":"#"},{"name":"attached","type":"flags.0?true"},{"name":"hash","type":"int"}],"type":"messages.RecentStickers"},{"id":"958863608","method":"messages.saveRecentSticker","params":[{"name":"flags","type":"#"},{"name":"attached","type":"flags.0?true"},{"name":"id","type":"InputDocument"},{"name":"unsave","type":"Bool"}],"type":"Bool"},{"id":"-1986437075","method":"messages.clearRecentStickers","params":[{"name":"flags","type":"#"},{"name":"attached","type":"flags.0?true"}],"type":"Bool"},{"id":"1475442322","method":"messages.getArchivedStickers","params":[{"name":"flags","type":"#"},{"name":"masks","type":"flags.0?true"},{"name":"offset_id","type":"long"},{"name":"limit","type":"int"}],"type":"messages.ArchivedStickers"},{"id":"457157256","method":"account.sendConfirmPhoneCode","params":[{"name":"hash","type":"string"},{"name":"settings","type":"CodeSettings"}],"type":"auth.SentCode"},{"id":"1596029123","method":"account.confirmPhone","params":[{"name":"phone_code_hash","type":"string"},{"name":"phone_code","type":"string"}],"type":"Bool"},{"id":"-122669393","method":"channels.getAdminedPublicChannels","params":[{"name":"flags","type":"#"},{"name":"by_location","type":"flags.0?true"},{"name":"check_limit","type":"flags.1?true"}],"type":"messages.Chats"},{"id":"1706608543","method":"messages.getMaskStickers","params":[{"name":"hash","type":"int"}],"type":"messages.AllStickers"},{"id":"-866424884","method":"messages.getAttachedStickers","params":[{"name":"media","type":"InputStickeredMedia"}],"type":"Vector<StickerSetCovered>"},{"id":"-1907842680","method":"auth.dropTempAuthKeys","params":[{"name":"except_auth_keys","type":"Vector<long>"}],"type":"Bool"},{"id":"-1896289088","method":"messages.setGameScore","params":[{"name":"flags","type":"#"},{"name":"edit_message","type":"flags.0?true"},{"name":"force","type":"flags.1?true"},{"name":"peer","type":"InputPeer"},{"name":"id","type":"int"},{"name":"user_id","type":"InputUser"},{"name":"score","type":"int"}],"type":"Updates"},{"id":"363700068","method":"messages.setInlineGameScore","params":[{"name":"flags","type":"#"},{"name":"edit_message","type":"flags.0?true"},{"name":"force","type":"flags.1?true"},{"name":"id","type":"InputBotInlineMessageID"},{"name":"user_id","type":"InputUser"},{"name":"score","type":"int"}],"type":"Bool"},{"id":"-400399203","method":"messages.getGameHighScores","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"int"},{"name":"user_id","type":"InputUser"}],"type":"messages.HighScores"},{"id":"258170395","method":"messages.getInlineGameHighScores","params":[{"name":"id","type":"InputBotInlineMessageID"},{"name":"user_id","type":"InputUser"}],"type":"messages.HighScores"},{"id":"218777796","method":"messages.getCommonChats","params":[{"name":"user_id","type":"InputUser"},{"name":"max_id","type":"int"},{"name":"limit","type":"int"}],"type":"messages.Chats"},{"id":"-341307408","method":"messages.getAllChats","params":[{"name":"except_ids","type":"Vector<int>"}],"type":"messages.Chats"},{"id":"-333262899","method":"help.setBotUpdatesStatus","params":[{"name":"pending_updates_count","type":"int"},{"name":"message","type":"string"}],"type":"Bool"},{"id":"852135825","method":"messages.getWebPage","params":[{"name":"url","type":"string"},{"name":"hash","type":"int"}],"type":"WebPage"},{"id":"-1489903017","method":"messages.toggleDialogPin","params":[{"name":"flags","type":"#"},{"name":"pinned","type":"flags.0?true"},{"name":"peer","type":"InputDialogPeer"}],"type":"Bool"},{"id":"991616823","method":"messages.reorderPinnedDialogs","params":[{"name":"flags","type":"#"},{"name":"force","type":"flags.0?true"},{"name":"folder_id","type":"int"},{"name":"order","type":"Vector<InputDialogPeer>"}],"type":"Bool"},{"id":"-692498958","method":"messages.getPinnedDialogs","params":[{"name":"folder_id","type":"int"}],"type":"messages.PeerDialogs"},{"id":"-1440257555","method":"bots.sendCustomRequest","params":[{"name":"custom_method","type":"string"},{"name":"params","type":"DataJSON"}],"type":"DataJSON"},{"id":"-434028723","method":"bots.answerWebhookJSONQuery","params":[{"name":"query_id","type":"long"},{"name":"data","type":"DataJSON"}],"type":"Bool"},{"id":"619086221","method":"upload.getWebFile","params":[{"name":"location","type":"InputWebFileLocation"},{"name":"offset","type":"int"},{"name":"limit","type":"int"}],"type":"upload.WebFile"},{"id":"-1712285883","method":"payments.getPaymentForm","params":[{"name":"msg_id","type":"int"}],"type":"payments.PaymentForm"},{"id":"-1601001088","method":"payments.getPaymentReceipt","params":[{"name":"msg_id","type":"int"}],"type":"payments.PaymentReceipt"},{"id":"1997180532","method":"payments.validateRequestedInfo","params":[{"name":"flags","type":"#"},{"name":"save","type":"flags.0?true"},{"name":"msg_id","type":"int"},{"name":"info","type":"PaymentRequestedInfo"}],"type":"payments.ValidatedRequestedInfo"},{"id":"730364339","method":"payments.sendPaymentForm","params":[{"name":"flags","type":"#"},{"name":"msg_id","type":"int"},{"name":"requested_info_id","type":"flags.0?string"},{"name":"shipping_option_id","type":"flags.1?string"},{"name":"credentials","type":"InputPaymentCredentials"}],"type":"payments.PaymentResult"},{"id":"1151208273","method":"account.getTmpPassword","params":[{"name":"password","type":"InputCheckPasswordSRP"},{"name":"period","type":"int"}],"type":"account.TmpPassword"},{"id":"578650699","method":"payments.getSavedInfo","params":[],"type":"payments.SavedInfo"},{"id":"-667062079","method":"payments.clearSavedInfo","params":[{"name":"flags","type":"#"},{"name":"credentials","type":"flags.0?true"},{"name":"info","type":"flags.1?true"}],"type":"Bool"},{"id":"-436833542","method":"messages.setBotShippingResults","params":[{"name":"flags","type":"#"},{"name":"query_id","type":"long"},{"name":"error","type":"flags.0?string"},{"name":"shipping_options","type":"flags.1?Vector<ShippingOption>"}],"type":"Bool"},{"id":"163765653","method":"messages.setBotPrecheckoutResults","params":[{"name":"flags","type":"#"},{"name":"success","type":"flags.1?true"},{"name":"query_id","type":"long"},{"name":"error","type":"flags.0?string"}],"type":"Bool"},{"id":"-1680314774","method":"stickers.createStickerSet","params":[{"name":"flags","type":"#"},{"name":"masks","type":"flags.0?true"},{"name":"user_id","type":"InputUser"},{"name":"title","type":"string"},{"name":"short_name","type":"string"},{"name":"stickers","type":"Vector<InputStickerSetItem>"}],"type":"messages.StickerSet"},{"id":"-143257775","method":"stickers.removeStickerFromSet","params":[{"name":"sticker","type":"InputDocument"}],"type":"messages.StickerSet"},{"id":"-4795190","method":"stickers.changeStickerPosition","params":[{"name":"sticker","type":"InputDocument"},{"name":"position","type":"int"}],"type":"messages.StickerSet"},{"id":"-2041315650","method":"stickers.addStickerToSet","params":[{"name":"stickerset","type":"InputStickerSet"},{"name":"sticker","type":"InputStickerSetItem"}],"type":"messages.StickerSet"},{"id":"1369162417","method":"messages.uploadMedia","params":[{"name":"peer","type":"InputPeer"},{"name":"media","type":"InputMedia"}],"type":"MessageMedia"},{"id":"1430593449","method":"phone.getCallConfig","params":[],"type":"DataJSON"},{"id":"1124046573","method":"phone.requestCall","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.0?true"},{"name":"user_id","type":"InputUser"},{"name":"random_id","type":"int"},{"name":"g_a_hash","type":"bytes"},{"name":"protocol","type":"PhoneCallProtocol"}],"type":"phone.PhoneCall"},{"id":"1003664544","method":"phone.acceptCall","params":[{"name":"peer","type":"InputPhoneCall"},{"name":"g_b","type":"bytes"},{"name":"protocol","type":"PhoneCallProtocol"}],"type":"phone.PhoneCall"},{"id":"788404002","method":"phone.confirmCall","params":[{"name":"peer","type":"InputPhoneCall"},{"name":"g_a","type":"bytes"},{"name":"key_fingerprint","type":"long"},{"name":"protocol","type":"PhoneCallProtocol"}],"type":"phone.PhoneCall"},{"id":"399855457","method":"phone.receivedCall","params":[{"name":"peer","type":"InputPhoneCall"}],"type":"Bool"},{"id":"-1295269440","method":"phone.discardCall","params":[{"name":"flags","type":"#"},{"name":"video","type":"flags.0?true"},{"name":"peer","type":"InputPhoneCall"},{"name":"duration","type":"int"},{"name":"reason","type":"PhoneCallDiscardReason"},{"name":"connection_id","type":"long"}],"type":"Updates"},{"id":"1508562471","method":"phone.setCallRating","params":[{"name":"flags","type":"#"},{"name":"user_initiative","type":"flags.0?true"},{"name":"peer","type":"InputPhoneCall"},{"name":"rating","type":"int"},{"name":"comment","type":"string"}],"type":"Updates"},{"id":"662363518","method":"phone.saveCallDebug","params":[{"name":"peer","type":"InputPhoneCall"},{"name":"debug","type":"DataJSON"}],"type":"Bool"},{"id":"536919235","method":"upload.getCdnFile","params":[{"name":"file_token","type":"bytes"},{"name":"offset","type":"int"},{"name":"limit","type":"int"}],"type":"upload.CdnFile"},{"id":"-1691921240","method":"upload.reuploadCdnFile","params":[{"name":"file_token","type":"bytes"},{"name":"request_token","type":"bytes"}],"type":"Vector<FileHash>"},{"id":"1375900482","method":"help.getCdnConfig","params":[],"type":"CdnConfig"},{"id":"-219008246","method":"langpack.getLangPack","params":[{"name":"lang_pack","type":"string"},{"name":"lang_code","type":"string"}],"type":"LangPackDifference"},{"id":"-269862909","method":"langpack.getStrings","params":[{"name":"lang_pack","type":"string"},{"name":"lang_code","type":"string"},{"name":"keys","type":"Vector<string>"}],"type":"Vector<LangPackString>"},{"id":"-845657435","method":"langpack.getDifference","params":[{"name":"lang_pack","type":"string"},{"name":"lang_code","type":"string"},{"name":"from_version","type":"int"}],"type":"LangPackDifference"},{"id":"1120311183","method":"langpack.getLanguages","params":[{"name":"lang_pack","type":"string"}],"type":"Vector<LangPackLanguage>"},{"id":"1920559378","method":"channels.editBanned","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"},{"name":"banned_rights","type":"ChatBannedRights"}],"type":"Updates"},{"id":"870184064","method":"channels.getAdminLog","params":[{"name":"flags","type":"#"},{"name":"channel","type":"InputChannel"},{"name":"q","type":"string"},{"name":"events_filter","type":"flags.0?ChannelAdminLogEventsFilter"},{"name":"admins","type":"flags.1?Vector<InputUser>"},{"name":"max_id","type":"long"},{"name":"min_id","type":"long"},{"name":"limit","type":"int"}],"type":"channels.AdminLogResults"},{"id":"1302676017","method":"upload.getCdnFileHashes","params":[{"name":"file_token","type":"bytes"},{"name":"offset","type":"int"}],"type":"Vector<FileHash>"},{"id":"-914493408","method":"messages.sendScreenshotNotification","params":[{"name":"peer","type":"InputPeer"},{"name":"reply_to_msg_id","type":"int"},{"name":"random_id","type":"long"}],"type":"Updates"},{"id":"-359881479","method":"channels.setStickers","params":[{"name":"channel","type":"InputChannel"},{"name":"stickerset","type":"InputStickerSet"}],"type":"Bool"},{"id":"567151374","method":"messages.getFavedStickers","params":[{"name":"hash","type":"int"}],"type":"messages.FavedStickers"},{"id":"-1174420133","method":"messages.faveSticker","params":[{"name":"id","type":"InputDocument"},{"name":"unfave","type":"Bool"}],"type":"Bool"},{"id":"-357180360","method":"channels.readMessageContents","params":[{"name":"channel","type":"InputChannel"},{"name":"id","type":"Vector<int>"}],"type":"Bool"},{"id":"-2020263951","method":"contacts.resetSaved","params":[],"type":"Bool"},{"id":"1180140658","method":"messages.getUnreadMentions","params":[{"name":"peer","type":"InputPeer"},{"name":"offset_id","type":"int"},{"name":"add_offset","type":"int"},{"name":"limit","type":"int"},{"name":"max_id","type":"int"},{"name":"min_id","type":"int"}],"type":"messages.Messages"},{"id":"-1355375294","method":"channels.deleteHistory","params":[{"name":"channel","type":"InputChannel"},{"name":"max_id","type":"int"}],"type":"Bool"},{"id":"1036054804","method":"help.getRecentMeUrls","params":[{"name":"referer","type":"string"}],"type":"help.RecentMeUrls"},{"id":"-356796084","method":"channels.togglePreHistoryHidden","params":[{"name":"channel","type":"InputChannel"},{"name":"enabled","type":"Bool"}],"type":"Updates"},{"id":"251759059","method":"messages.readMentions","params":[{"name":"peer","type":"InputPeer"}],"type":"messages.AffectedHistory"},{"id":"-1144759543","method":"messages.getRecentLocations","params":[{"name":"peer","type":"InputPeer"},{"name":"limit","type":"int"},{"name":"hash","type":"int"}],"type":"messages.Messages"},{"id":"-872345397","method":"messages.sendMultiMedia","params":[{"name":"flags","type":"#"},{"name":"silent","type":"flags.5?true"},{"name":"background","type":"flags.6?true"},{"name":"clear_draft","type":"flags.7?true"},{"name":"peer","type":"InputPeer"},{"name":"reply_to_msg_id","type":"flags.0?int"},{"name":"multi_media","type":"Vector<InputSingleMedia>"},{"name":"schedule_date","type":"flags.10?int"}],"type":"Updates"},{"id":"1347929239","method":"messages.uploadEncryptedFile","params":[{"name":"peer","type":"InputEncryptedChat"},{"name":"file","type":"InputEncryptedFile"}],"type":"EncryptedFile"},{"id":"405695855","method":"account.getWebAuthorizations","params":[],"type":"account.WebAuthorizations"},{"id":"755087855","method":"account.resetWebAuthorization","params":[{"name":"hash","type":"long"}],"type":"Bool"},{"id":"1747789204","method":"account.resetWebAuthorizations","params":[],"type":"Bool"},{"id":"-1028140917","method":"messages.searchStickerSets","params":[{"name":"flags","type":"#"},{"name":"exclude_featured","type":"flags.0?true"},{"name":"q","type":"string"},{"name":"hash","type":"int"}],"type":"messages.FoundStickerSets"},{"id":"-956147407","method":"upload.getFileHashes","params":[{"name":"location","type":"InputFileLocation"},{"name":"offset","type":"int"}],"type":"Vector<FileHash>"},{"id":"1031231713","method":"help.getProxyData","params":[],"type":"help.ProxyData"},{"id":"749019089","method":"help.getTermsOfServiceUpdate","params":[],"type":"help.TermsOfServiceUpdate"},{"id":"-294455398","method":"help.acceptTermsOfService","params":[{"name":"id","type":"DataJSON"}],"type":"Bool"},{"id":"-1299661699","method":"account.getAllSecureValues","params":[],"type":"Vector<SecureValue>"},{"id":"1936088002","method":"account.getSecureValue","params":[{"name":"types","type":"Vector<SecureValueType>"}],"type":"Vector<SecureValue>"},{"id":"-1986010339","method":"account.saveSecureValue","params":[{"name":"value","type":"InputSecureValue"},{"name":"secure_secret_id","type":"long"}],"type":"SecureValue"},{"id":"-1199522741","method":"account.deleteSecureValue","params":[{"name":"types","type":"Vector<SecureValueType>"}],"type":"Bool"},{"id":"-1865902923","method":"users.setSecureValueErrors","params":[{"name":"id","type":"InputUser"},{"name":"errors","type":"Vector<SecureValueError>"}],"type":"Bool"},{"id":"-1200903967","method":"account.getAuthorizationForm","params":[{"name":"bot_id","type":"int"},{"name":"scope","type":"string"},{"name":"public_key","type":"string"}],"type":"account.AuthorizationForm"},{"id":"-419267436","method":"account.acceptAuthorization","params":[{"name":"bot_id","type":"int"},{"name":"scope","type":"string"},{"name":"public_key","type":"string"},{"name":"value_hashes","type":"Vector<SecureValueHash>"},{"name":"credentials","type":"SecureCredentialsEncrypted"}],"type":"Bool"},{"id":"-1516022023","method":"account.sendVerifyPhoneCode","params":[{"name":"phone_number","type":"string"},{"name":"settings","type":"CodeSettings"}],"type":"auth.SentCode"},{"id":"1305716726","method":"account.verifyPhone","params":[{"name":"phone_number","type":"string"},{"name":"phone_code_hash","type":"string"},{"name":"phone_code","type":"string"}],"type":"Bool"},{"id":"1880182943","method":"account.sendVerifyEmailCode","params":[{"name":"email","type":"string"}],"type":"account.SentEmailCode"},{"id":"-323339813","method":"account.verifyEmail","params":[{"name":"email","type":"string"},{"name":"code","type":"string"}],"type":"Bool"},{"id":"1072547679","method":"help.getDeepLinkInfo","params":[{"name":"path","type":"string"}],"type":"help.DeepLinkInfo"},{"id":"-2098076769","method":"contacts.getSaved","params":[],"type":"Vector<SavedContact>"},{"id":"-2092831552","method":"channels.getLeftChannels","params":[{"name":"offset","type":"int"}],"type":"messages.Chats"},{"id":"-262453244","method":"account.initTakeoutSession","params":[{"name":"flags","type":"#"},{"name":"contacts","type":"flags.0?true"},{"name":"message_users","type":"flags.1?true"},{"name":"message_chats","type":"flags.2?true"},{"name":"message_megagroups","type":"flags.3?true"},{"name":"message_channels","type":"flags.4?true"},{"name":"files","type":"flags.5?true"},{"name":"file_max_size","type":"flags.5?int"}],"type":"account.Takeout"},{"id":"489050862","method":"account.finishTakeoutSession","params":[{"name":"flags","type":"#"},{"name":"success","type":"flags.0?true"}],"type":"Bool"},{"id":"486505992","method":"messages.getSplitRanges","params":[],"type":"Vector<MessageRange>"},{"id":"911373810","method":"invokeWithMessagesRange","params":[{"name":"range","type":"MessageRange"},{"name":"query","type":"!X"}],"type":"X"},{"id":"-1398145746","method":"invokeWithTakeout","params":[{"name":"takeout_id","type":"long"},{"name":"query","type":"!X"}],"type":"X"},{"id":"-1031349873","method":"messages.markDialogUnread","params":[{"name":"flags","type":"#"},{"name":"unread","type":"flags.0?true"},{"name":"peer","type":"InputDialogPeer"}],"type":"Bool"},{"id":"585256482","method":"messages.getDialogUnreadMarks","params":[],"type":"Vector<DialogPeer>"},{"id":"-2062238246","method":"contacts.toggleTopPeers","params":[{"name":"enabled","type":"Bool"}],"type":"Bool"},{"id":"2119757468","method":"messages.clearAllDrafts","params":[],"type":"Bool"},{"id":"-1735311088","method":"help.getAppConfig","params":[],"type":"JSONValue"},{"id":"1862465352","method":"help.saveAppLog","params":[{"name":"events","type":"Vector<InputAppEvent>"}],"type":"Bool"},{"id":"-966677240","method":"help.getPassportConfig","params":[{"name":"hash","type":"int"}],"type":"help.PassportConfig"},{"id":"1784243458","method":"langpack.getLanguage","params":[{"name":"lang_pack","type":"string"},{"name":"lang_code","type":"string"}],"type":"LangPackLanguage"},{"id":"-760547348","method":"messages.updatePinnedMessage","params":[{"name":"flags","type":"#"},{"name":"silent","type":"flags.0?true"},{"name":"peer","type":"InputPeer"},{"name":"id","type":"int"}],"type":"Updates"},{"id":"-1881204448","method":"account.confirmPasswordEmail","params":[{"name":"code","type":"string"}],"type":"Bool"},{"id":"2055154197","method":"account.resendPasswordEmail","params":[],"type":"Bool"},{"id":"-1043606090","method":"account.cancelPasswordEmail","params":[],"type":"Bool"},{"id":"-748624084","method":"help.getSupportName","params":[],"type":"help.SupportName"},{"id":"59377875","method":"help.getUserInfo","params":[{"name":"user_id","type":"InputUser"}],"type":"help.UserInfo"},{"id":"1723407216","method":"help.editUserInfo","params":[{"name":"user_id","type":"InputUser"},{"name":"message","type":"string"},{"name":"entities","type":"Vector<MessageEntity>"}],"type":"help.UserInfo"},{"id":"-1626880216","method":"account.getContactSignUpNotification","params":[],"type":"Bool"},{"id":"-806076575","method":"account.setContactSignUpNotification","params":[{"name":"silent","type":"Bool"}],"type":"Bool"},{"id":"1398240377","method":"account.getNotifyExceptions","params":[{"name":"flags","type":"#"},{"name":"compare_sound","type":"flags.1?true"},{"name":"peer","type":"flags.0?InputNotifyPeer"}],"type":"Updates"},{"id":"283795844","method":"messages.sendVote","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"options","type":"Vector<bytes>"}],"type":"Updates"},{"id":"1941660731","method":"messages.getPollResults","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"}],"type":"Updates"},{"id":"1848369232","method":"messages.getOnlines","params":[{"name":"peer","type":"InputPeer"}],"type":"ChatOnlines"},{"id":"-2127811866","method":"messages.getStatsURL","params":[{"name":"flags","type":"#"},{"name":"dark","type":"flags.0?true"},{"name":"peer","type":"InputPeer"},{"name":"params","type":"string"}],"type":"StatsURL"},{"id":"-554301545","method":"messages.editChatAbout","params":[{"name":"peer","type":"InputPeer"},{"name":"about","type":"string"}],"type":"Bool"},{"id":"-1517917375","method":"messages.editChatDefaultBannedRights","params":[{"name":"peer","type":"InputPeer"},{"name":"banned_rights","type":"ChatBannedRights"}],"type":"Updates"},{"id":"-57811990","method":"account.getWallPaper","params":[{"name":"wallpaper","type":"InputWallPaper"}],"type":"WallPaper"},{"id":"-578472351","method":"account.uploadWallPaper","params":[{"name":"file","type":"InputFile"},{"name":"mime_type","type":"string"},{"name":"settings","type":"WallPaperSettings"}],"type":"WallPaper"},{"id":"1817860919","method":"account.saveWallPaper","params":[{"name":"wallpaper","type":"InputWallPaper"},{"name":"unsave","type":"Bool"},{"name":"settings","type":"WallPaperSettings"}],"type":"Bool"},{"id":"-18000023","method":"account.installWallPaper","params":[{"name":"wallpaper","type":"InputWallPaper"},{"name":"settings","type":"WallPaperSettings"}],"type":"Bool"},{"id":"-1153722364","method":"account.resetWallPapers","params":[],"type":"Bool"},{"id":"1457130303","method":"account.getAutoDownloadSettings","params":[],"type":"account.AutoDownloadSettings"},{"id":"1995661875","method":"account.saveAutoDownloadSettings","params":[{"name":"flags","type":"#"},{"name":"low","type":"flags.0?true"},{"name":"high","type":"flags.1?true"},{"name":"settings","type":"AutoDownloadSettings"}],"type":"Bool"},{"id":"899735650","method":"messages.getEmojiKeywords","params":[{"name":"lang_code","type":"string"}],"type":"EmojiKeywordsDifference"},{"id":"352892591","method":"messages.getEmojiKeywordsDifference","params":[{"name":"lang_code","type":"string"},{"name":"from_version","type":"int"}],"type":"EmojiKeywordsDifference"},{"id":"1318675378","method":"messages.getEmojiKeywordsLanguages","params":[{"name":"lang_codes","type":"Vector<string>"}],"type":"Vector<EmojiLanguage>"},{"id":"-709817306","method":"messages.getEmojiURL","params":[{"name":"lang_code","type":"string"}],"type":"EmojiURL"},{"id":"1749536939","method":"folders.editPeerFolders","params":[{"name":"folder_peers","type":"Vector<InputFolderPeer>"}],"type":"Updates"},{"id":"472471681","method":"folders.deleteFolder","params":[{"name":"folder_id","type":"int"}],"type":"Updates"},{"id":"1932455680","method":"messages.getSearchCounters","params":[{"name":"peer","type":"InputPeer"},{"name":"filters","type":"Vector<MessagesFilter>"}],"type":"Vector<messages.SearchCounter>"},{"id":"-170208392","method":"channels.getGroupsForDiscussion","params":[],"type":"messages.Chats"},{"id":"1079520178","method":"channels.setDiscussionGroup","params":[{"name":"broadcast","type":"InputChannel"},{"name":"group","type":"InputChannel"}],"type":"Bool"},{"id":"-482388461","method":"messages.requestUrlAuth","params":[{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"button_id","type":"int"}],"type":"UrlAuthResult"},{"id":"-148247912","method":"messages.acceptUrlAuth","params":[{"name":"flags","type":"#"},{"name":"write_allowed","type":"flags.0?true"},{"name":"peer","type":"InputPeer"},{"name":"msg_id","type":"int"},{"name":"button_id","type":"int"}],"type":"UrlAuthResult"},{"id":"1336717624","method":"messages.hidePeerSettingsBar","params":[{"name":"peer","type":"InputPeer"}],"type":"Bool"},{"id":"-386636848","method":"contacts.addContact","params":[{"name":"flags","type":"#"},{"name":"add_phone_privacy_exception","type":"flags.0?true"},{"name":"id","type":"InputUser"},{"name":"first_name","type":"string"},{"name":"last_name","type":"string"},{"name":"phone","type":"string"}],"type":"Updates"},{"id":"-130964977","method":"contacts.acceptContact","params":[{"name":"id","type":"InputUser"}],"type":"Updates"},{"id":"-1892102881","method":"channels.editCreator","params":[{"name":"channel","type":"InputChannel"},{"name":"user_id","type":"InputUser"},{"name":"password","type":"InputCheckPasswordSRP"}],"type":"Updates"},{"id":"171270230","method":"contacts.getLocated","params":[{"name":"geo_point","type":"InputGeoPoint"}],"type":"Updates"},{"id":"1491484525","method":"channels.editLocation","params":[{"name":"channel","type":"InputChannel"},{"name":"geo_point","type":"InputGeoPoint"},{"name":"address","type":"string"}],"type":"Bool"},{"id":"-304832784","method":"channels.toggleSlowMode","params":[{"name":"channel","type":"InputChannel"},{"name":"seconds","type":"int"}],"type":"Updates"},{"id":"-490575781","method":"messages.getScheduledHistory","params":[{"name":"peer","type":"InputPeer"},{"name":"hash","type":"int"}],"type":"messages.Messages"},{"id":"-1111817116","method":"messages.getScheduledMessages","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"}],"type":"messages.Messages"},{"id":"-1120369398","method":"messages.sendScheduledMessages","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"}],"type":"Updates"},{"id":"1504586518","method":"messages.deleteScheduledMessages","params":[{"name":"peer","type":"InputPeer"},{"name":"id","type":"Vector<int>"}],"type":"Updates"},{"id":"473805619","method":"account.uploadTheme","params":[{"name":"flags","type":"#"},{"name":"file","type":"InputFile"},{"name":"thumb","type":"flags.0?InputFile"},{"name":"file_name","type":"string"},{"name":"mime_type","type":"string"}],"type":"Document"},{"id":"729808255","method":"account.createTheme","params":[{"name":"slug","type":"string"},{"name":"title","type":"string"},{"name":"document","type":"InputDocument"}],"type":"Theme"},{"id":"999203330","method":"account.updateTheme","params":[{"name":"flags","type":"#"},{"name":"format","type":"string"},{"name":"theme","type":"InputTheme"},{"name":"slug","type":"flags.0?string"},{"name":"title","type":"flags.1?string"},{"name":"document","type":"flags.2?InputDocument"}],"type":"Theme"},{"id":"-229175188","method":"account.saveTheme","params":[{"name":"theme","type":"InputTheme"},{"name":"unsave","type":"Bool"}],"type":"Bool"},{"id":"2061776695","method":"account.installTheme","params":[{"name":"flags","type":"#"},{"name":"dark","type":"flags.0?true"},{"name":"format","type":"flags.1?string"},{"name":"theme","type":"flags.1?InputTheme"}],"type":"Bool"},{"id":"-1919060949","method":"account.getTheme","params":[{"name":"format","type":"string"},{"name":"theme","type":"InputTheme"},{"name":"document_id","type":"long"}],"type":"Theme"},{"id":"676939512","method":"account.getThemes","params":[{"name":"format","type":"string"},{"name":"hash","type":"int"}],"type":"account.Themes"}]};
        this.MTProto = {'constructors': [{'id': '481674261','predicate': 'vector','params': [],'type': 'Vector t'}, {'id': '85337187','predicate': 'resPQ','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'pq','type': 'bytes'}, {'name': 'server_public_key_fingerprints','type': 'Vector<long>'}],'type': 'ResPQ'}, {'id': '-2083955988','predicate': 'p_q_inner_data','params': [{'name': 'pq','type': 'bytes'}, {'name': 'p','type': 'bytes'}, {'name': 'q','type': 'bytes'}, {'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'new_nonce','type': 'int256'}],'type': 'P_Q_inner_data'}, {'id': '2043348061','predicate': 'server_DH_params_fail','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'new_nonce_hash','type': 'int128'}],'type': 'Server_DH_Params'}, {'id': '-790100132','predicate': 'server_DH_params_ok','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'encrypted_answer','type': 'bytes'}],'type': 'Server_DH_Params'}, {'id': '-1249309254','predicate': 'server_DH_inner_data','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'g','type': 'int'}, {'name': 'dh_prime','type': 'bytes'}, {'name': 'g_a','type': 'bytes'}, {'name': 'server_time','type': 'int'}],'type': 'Server_DH_inner_data'}, {'id': '1715713620','predicate': 'client_DH_inner_data','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'retry_id','type': 'long'}, {'name': 'g_b','type': 'bytes'}],'type': 'Client_DH_Inner_Data'}, {'id': '1003222836','predicate': 'dh_gen_ok','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'new_nonce_hash1','type': 'int128'}],'type': 'Set_client_DH_params_answer'}, {'id': '1188831161','predicate': 'dh_gen_retry','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'new_nonce_hash2','type': 'int128'}],'type': 'Set_client_DH_params_answer'}, {'id': '-1499615742','predicate': 'dh_gen_fail','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'new_nonce_hash3','type': 'int128'}],'type': 'Set_client_DH_params_answer'}, {'id': '-212046591','predicate': 'rpc_result','params': [{'name': 'req_msg_id','type': 'long'}, {'name': 'result','type': 'Object'}],'type': 'RpcResult'}, {'id': '558156313','predicate': 'rpc_error','params': [{'name': 'error_code','type': 'int'}, {'name': 'error_message','type': 'string'}],'type': 'RpcError'}, {'id': '1579864942','predicate': 'rpc_answer_unknown','params': [],'type': 'RpcDropAnswer'}, {'id': '-847714938','predicate': 'rpc_answer_dropped_running','params': [],'type': 'RpcDropAnswer'}, {'id': '-1539647305','predicate': 'rpc_answer_dropped','params': [{'name': 'msg_id','type': 'long'}, {'name': 'seq_no','type': 'int'}, {'name': 'bytes','type': 'int'}],'type': 'RpcDropAnswer'}, {'id': '155834844','predicate': 'future_salt','params': [{'name': 'valid_since','type': 'int'}, {'name': 'valid_until','type': 'int'}, {'name': 'salt','type': 'long'}],'type': 'FutureSalt'}, {'id': '-1370486635','predicate': 'future_salts','params': [{'name': 'req_msg_id','type': 'long'}, {'name': 'now','type': 'int'}, {'name': 'salts','type': 'vector<future_salt>'}],'type': 'FutureSalts'}, {'id': '880243653','predicate': 'pong','params': [{'name': 'msg_id','type': 'long'}, {'name': 'ping_id','type': 'long'}],'type': 'Pong'}, {'id': '-501201412','predicate': 'destroy_session_ok','params': [{'name': 'session_id','type': 'long'}],'type': 'DestroySessionRes'}, {'id': '1658015945','predicate': 'destroy_session_none','params': [{'name': 'session_id','type': 'long'}],'type': 'DestroySessionRes'}, {'id': '-1631450872','predicate': 'new_session_created','params': [{'name': 'first_msg_id','type': 'long'}, {'name': 'unique_id','type': 'long'}, {'name': 'server_salt','type': 'long'}],'type': 'NewSession'}, {'id': '1945237724','predicate': 'msg_container','params': [{'name': 'messages','type': 'vector<%Message>'}],'type': 'MessageContainer'}, {'id': '1538843921','predicate': 'message','params': [{'name': 'msg_id','type': 'long'}, {'name': 'seqno','type': 'int'}, {'name': 'bytes','type': 'int'}, {'name': 'body','type': 'Object'}],'type': 'Message'}, {'id': '-530561358','predicate': 'msg_copy','params': [{'name': 'orig_message','type': 'Message'}],'type': 'MessageCopy'}, {'id': '812830625','predicate': 'gzip_packed','params': [{'name': 'packed_data','type': 'bytes'}],'type': 'Object'}, {'id': '1658238041','predicate': 'msgs_ack','params': [{'name': 'msg_ids','type': 'Vector<long>'}],'type': 'MsgsAck'}, {'id': '-1477445615','predicate': 'bad_msg_notification','params': [{'name': 'bad_msg_id','type': 'long'}, {'name': 'bad_msg_seqno','type': 'int'}, {'name': 'error_code','type': 'int'}],'type': 'BadMsgNotification'}, {'id': '-307542917','predicate': 'bad_server_salt','params': [{'name': 'bad_msg_id','type': 'long'}, {'name': 'bad_msg_seqno','type': 'int'}, {'name': 'error_code','type': 'int'}, {'name': 'new_server_salt','type': 'long'}],'type': 'BadMsgNotification'}, {'id': '2105940488','predicate': 'msg_resend_req','params': [{'name': 'msg_ids','type': 'Vector<long>'}],'type': 'MsgResendReq'}, {'id': '-630588590','predicate': 'msgs_state_req','params': [{'name': 'msg_ids','type': 'Vector<long>'}],'type': 'MsgsStateReq'}, {'id': '81704317','predicate': 'msgs_state_info','params': [{'name': 'req_msg_id','type': 'long'}, {'name': 'info','type': 'bytes'}],'type': 'MsgsStateInfo'}, {'id': '-1933520591','predicate': 'msgs_all_info','params': [{'name': 'msg_ids','type': 'Vector<long>'}, {'name': 'info','type': 'bytes'}],'type': 'MsgsAllInfo'}, {'id': '661470918','predicate': 'msg_detailed_info','params': [{'name': 'msg_id','type': 'long'}, {'name': 'answer_msg_id','type': 'long'}, {'name': 'bytes','type': 'int'}, {'name': 'status','type': 'int'}],'type': 'MsgDetailedInfo'}, {'id': '-2137147681','predicate': 'msg_new_detailed_info','params': [{'name': 'answer_msg_id','type': 'long'}, {'name': 'bytes','type': 'int'}, {'name': 'status','type': 'int'}],'type': 'MsgDetailedInfo'}],'methods': [{'id': '1615239032','method': 'req_pq','params': [{'name': 'nonce','type': 'int128'}],'type': 'ResPQ'}, {'id': '-686627650','method': 'req_DH_params','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'p','type': 'bytes'}, {'name': 'q','type': 'bytes'}, {'name': 'public_key_fingerprint','type': 'long'}, {'name': 'encrypted_data','type': 'bytes'}],'type': 'Server_DH_Params'}, {'id': '-184262881','method': 'set_client_DH_params','params': [{'name': 'nonce','type': 'int128'}, {'name': 'server_nonce','type': 'int128'}, {'name': 'encrypted_data','type': 'bytes'}],'type': 'Set_client_DH_params_answer'}, {'id': '1491380032','method': 'rpc_drop_answer','params': [{'name': 'req_msg_id','type': 'long'}],'type': 'RpcDropAnswer'}, {'id': '-1188971260','method': 'get_future_salts','params': [{'name': 'num','type': 'int'}],'type': 'FutureSalts'}, {'id': '2059302892','method': 'ping','params': [{'name': 'ping_id','type': 'long'}],'type': 'Pong'}, {'id': '-213746804','method': 'ping_delay_disconnect','params': [{'name': 'ping_id','type': 'long'}, {'name': 'disconnect_delay','type': 'int'}],'type': 'Pong'}, {'id': '-414113498','method': 'destroy_session','params': [{'name': 'session_id','type': 'long'}],'type': 'DestroySessionRes'}, {'id': '-1835453025','method': 'http_wait','params': [{'name': 'max_delay','type': 'int'}, {'name': 'wait_after','type': 'int'}, {'name': 'max_wait','type': 'int'}],'type': 'HttpWait'}]};
    }

    attachToWindow() {
        window.Tgm = this;
    }
}

class BinData {
    constructor(opt) {
        this.init(opt);
        this.BOOL_TPL   = [0xbc799737,0x997275b5];
    }

    init(opt) {
        opt = opt || {};
        this.offset     = 0;

        if(opt.buffer) {
            this.buffer     = opt.buffer;
            this.maxLength  = opt.buffer.byteLength;
        } else {
            this.maxLength  = opt.maxLength || 2048;
            this.buffer     = new ArrayBuffer(this.maxLength);
        }

        this.byteView   = new Uint8Array(this.buffer);  
    }

    get tbuffer(){
        return this.buffer.slice(0,this.offset);
    }

    get tbytes(){
        return CryptoUtils.cloneArray(this.byteView.slice(0,this.offset));
    }

    freeSize() {
        return this.maxLength - this.offset;
    }

    storeInt(i) {
        let b = new Int32Array([i]);
        this.storeIntBytes(b.buffer,4);
    }

    storeBool(i) {
        this.storeInt(this.BOOL_TPL[0+i]);
    }

    storeIntBytes(bytes,length, reverse = false) {
        // if (bytes instanceof ArrayBuffer) {
        //     bytes = new Uint8Array(bytes)
        // }

        bytes = new Uint8Array(bytes);

        if(reverse) { bytes.reverse();}

        let len = bytes.length;

        if(length != len) {
            throw new Error(`storeIntBytes: incorrect BytesArray length ${len}, expected ${length}`)
        }

        if(this.freeSize() - len < 0){
            throw new Error(`buffer is full`)
        }

        this.byteView.set(bytes, this.offset);
        this.offset += len;
    }

    storeLong(bytes) {
        this.storeIntBytes(bytes,8,true);
    }

    storeDouble(f) {
        let buffer = new ArrayBuffer(8);
        let intView = new Int32Array(buffer);
        let doubleView = new Float64Array(buffer);

        doubleView[0] = f;

        intView.forEach((element)=>{
            this.storeInt(element);
        });
    }

    storeString(s){
        this.storeAny(s,(t)=>{
            var sUTF8 = unescape(encodeURIComponent(t === undefined ? '' : t));
            return [sUTF8,sUTF8.length];
        },(b,len)=>{
            for (var i = 0; i < len; i++) {
                this.byteView[this.offset++] = b.charCodeAt(i);
                this.offset += len;
            }           
        });
    }

    storeBytes(bytes){
        this.storeAny(bytes,(b)=>{
            if (b instanceof ArrayBuffer) {
                b = new Uint8Array(b)
            }
            else if (b === undefined) {
                b = []
            }
            return [b,b.byteLength || b.length];
        },(b,len)=>{
            this.byteView.set(b, this.offset)
            this.offset += len      
        });
    }

    storeAny(val, prepare, store) {

        var [bytes,len] = prepare(val);

        if(this.freeSize() - len - 8 < 0){
            throw new Error(`buffer is full`);
        }

        if (len <= 253) {
            this.byteView[this.offset++] = len
        } else {
            this.byteView[this.offset++] = 254
            this.byteView[this.offset++] = len & 0xFF
            this.byteView[this.offset++] = (len & 0xFF00) >> 8
            this.byteView[this.offset++] = (len & 0xFF0000) >> 16
        }

        store(bytes,len);

        // Padding
        while (this.offset % 4) {
            this.byteView[this.offset++] = 0
        }
    }

    storeRawBytes(bytes, field) {
        if (bytes instanceof ArrayBuffer) {
            bytes = new Uint8Array(bytes)
        }
        var len = bytes.length

        if(this.freeSize() - len< 0){
            throw new Error(`buffer is full`);
        }

        this.byteView.set(bytes, this.offset);
        this.offset += len;
    }

    storeParams(data, obj, schema) {
        data.params.forEach((param)=>{
            let type = param.type;
            if (type.indexOf('?') !== -1) {
                let condType = type.split('?')
                let fieldBit = condType[0].split('.')
                if (!(obj[fieldBit[0]] & (1 << fieldBit[1]))) {
                    return;
                }
                type = condType[1]
            }
    
            this.storeObject(obj[param.name], type, schema) ;       
        });
    }

    storeMethod(methodName, params, schema) {
        let methodData = false;

        for (let i = 0; i < schema.methods.length; i++) {
            if (schema.methods[i].method == methodName) {
                methodData = schema.methods[i];
                break;
            }
        }

        if (!methodData) {
            throw new Error('No method ' + methodName + ' found');
        }

        this.storeInt(CryptoUtils.intToUint(methodData.id));
        this.storeParams(methodData, params, schema);
        return methodData.type;
    }

    storeObject(obj, type, schema) {
        switch (type) {
            case '#':
            case 'int':
              return this.storeInt(obj)
            case 'long':
              return this.storeLong(obj)
            case 'int128':
              return this.storeIntBytes(obj, 16)
            case 'int256':
              return this.storeIntBytes(obj, 32)
            case 'int512':
              return this.storeIntBytes(obj, 64)
            case 'string':
              return this.storeString(obj)
            case 'bytes':
              return this.storeBytes(obj)
            case 'double':
              return this.storeDouble(obj)
            case 'Bool':
              return this.storeBool(obj)
            case 'true':
              return
        }

        if (CryptoUtils.isArray(obj)) {
            if (type.substr(0, 6) == 'Vector') {
                this.storeInt(0x1cb5c415)
            }
            else if (type.substr(0, 6) != 'vector') {
                throw new Error('Invalid vector type ' + type)
            }

            let itemType = type.substr(7, type.length - 8);
            this.storeInt(obj.length)
            for (let i = 0; i < obj.length; i++) {
                this.storeObject(obj[i], itemType, schema)
            }
            return true;
        }
        else if (type.substr(0, 6).toLowerCase() == 'vector') {
            throw new Error('Invalid vector object')
        }

        if (!CryptoUtils.isObject(obj)) {
            throw new Error('Invalid object for type ' + type)
        }

        var predicate = obj['_']
        var isBare = false
        var constructorData = false;

        if (isBare = (type.charAt(0) == '%')) {
            type = type.substr(1);
        }

        for (let i = 0; i < schema.constructors.length; i++) {
            if (schema.constructors[i].predicate == predicate) {
                constructorData = schema.constructors[i];
                break;
            }
        }
        if (!constructorData) {
            throw new Error('No predicate ' + predicate + ' found')
        }

        if (predicate == type) {
            isBare = true;
        }

        if (!isBare) {
            this.storeInt(CryptoUtils.intToUint(constructorData.id));
        }

        this.storeParams(constructorData, obj, schema);
        return constructorData.type;
    }

    fetchInt() {
        let b = this.fetchIntBytes(4,true);
        let k = new Int32Array((new Uint8Array(b)).buffer);
        return k[0];
    }

    fetchDouble() {
        var buffer = new ArrayBuffer(8);
        var intView = new Int32Array(buffer);
        var doubleView = new Float64Array(buffer);
        
        intView[0] = this.fetchInt();
        intView[1] = this.fetchInt();
        
        return doubleView[0];
    }

    fetchLong() {
        return this.fetchIntBytes(8).reverse();
    }

    fetchBool(schema) {
        var i = this.fetchInt();
        if (this.BOOL_TPL[1] == i) {
            return true;
        } else if (this.BOOL_TPL[0] == i) {
            return false;
        }

        this.offset -= 4;
        return this.fetchObject('Object',schema);
    }

    fetchString (){
        var len = this.byteView[this.offset++]

        if (len == 254) {
            len = this.byteView[this.offset++] | (this.byteView[this.offset++] << 8) | (this.byteView[this.offset++] << 16)
        }

        var sUTF8 = '';

        for (let i = 0; i < len; i++) {
            sUTF8 += String.fromCharCode(this.byteView[this.offset++]);
        }

        // Padding
        while (this.offset % 4) {
            this.offset++;
        }

        var s;

        try {
            s = decodeURIComponent(escape(sUTF8));
        } catch (e) {
            s = sUTF8;
        }

        return s;
    }

    fetchBytes() {
        var len = this.byteView[this.offset++];

        if (len == 254) {
            len = this.byteView[this.offset++] | (this.byteView[this.offset++] << 8) | (this.byteView[this.offset++] << 16);
        }

        var bytes = [];
        for (let i = 0; i < len; i++) {
            bytes.push(this.byteView[this.offset++]);
        }

        // Padding
        while (this.offset % 4) {
            this.offset++;
        }

        return bytes;
    }

    fetchIntBytes(len) {
        if (len % 4) {
            throw new Error('Invalid bytes: ' + len);
        }

        var bytes = [];
        for (let i = 0; i < len; i++) {
            bytes.push(this.byteView[this.offset++]);
        }

        return bytes;
    }

    fetchRawBytes(len) {
        if (len === false) {
            len = this.fetchInt((field || '') + '_length');
            if (len > this.byteView.byteLength) {
                throw new Error('Invalid raw bytes length: ' + len + ', buffer len: ' + this.byteView.byteLength);
            }
        }

        var bytes = [];
        for (var i = 0; i < len; i++) {
            bytes.push(this.byteView[this.offset++]);
        }

        return bytes;
    }

    fetchObject(type,schema) {
        switch (type) {
            case '#':
            case 'int':return this.fetchInt()
            case 'long':return this.fetchLong()
            case 'int128':return this.fetchIntBytes(16)
            case 'int256':return this.fetchIntBytes(32)
            case 'int512':return this.fetchIntBytes(64)
            case 'string':return this.fetchString()
            case 'bytes':return this.fetchBytes()
            case 'double':return this.fetchDouble()
            case 'Bool':return this.fetchBool(schema)
            case 'true':return true
        }

        if (type.substr(0, 6) == 'Vector' || type.substr(0, 6) == 'vector') {
            if (type.charAt(0) == 'V') {
                var constructor = this.fetchInt();
                var constructorCmp = CryptoUtils.uintToInt(constructor);
                if (constructorCmp != 0x1cb5c415) {
                    throw new Error('Invalid vector constructor ' + constructor);
                }
            }
            let len = this.fetchInt();
            let result = [];

            if (len > 0) {
                var itemType = type.substr(7, type.length - 8);
                for (let i = 0; i < len; i++) {
                    result.push(this.fetchObject(itemType,schema));
                }
            }

            return result;
        }

        let predicate = false;
        let constructorData = false;

        if (type.charAt(0) == '%') {
            var checkType = type.substr(1)
            for (var i = 0; i < schema.constructors.length; i++) {
              if (schema.constructors[i].type == checkType) {
                constructorData = schema.constructors[i]
                break
              }
            }
            if (!constructorData) {
              throw new Error('Constructor not found for type: ' + type)
            }
        }
        else if (type.charAt(0) >= 97 && type.charAt(0) <= 122) {
            for (var i = 0; i < schema.constructors.length; i++) {
                if (schema.constructors[i].predicate == type) {
                    constructorData = schema.constructors[i]
                    break
                }
            }
            if (!constructorData) {
                throw new Error('Constructor not found for predicate: ' + type)
            }
        }else {
            var constructor = this.fetchInt();
            var constructorCmp = CryptoUtils.uintToInt(constructor);

            var index = schema.constructorsIndex
            if (!index) {
                schema.constructorsIndex = index = {}
                for (var i = 0; i < schema.constructors.length; i++) {
                    index[schema.constructors[i].id] = i;
                }
            }

            var i = index[constructorCmp];
            if (i) {
                constructorData = schema.constructors[i];
            }

            if (!constructorData) {
                throw new Error('Constructor not found: ' + constructor + ' ' + this.fetchInt() + ' ' + this.fetchInt())
            }
        }

        predicate = constructorData.predicate;

        let result = {'_': predicate}

        constructorData.params.forEach((param)=>{
            let type = param.type;
            if (type == '#' && result.pFlags === undefined) {
                result.pFlags = {};
            }
            let isCond;
            if (isCond = (type.indexOf('?') !== -1)) {
                let condType = type.split('?');
                let fieldBit = condType[0].split('.');

                if (!(result[fieldBit[0]] & (1 << fieldBit[1]))) {
                    return;
                }
                type = condType[1]
            }

            let value = this.fetchObject(type,schema);

            if (isCond && type === 'true') {
                result.pFlags[param.name] = value;
            } else {
                result[param.name] = value;
            }
        });

      return result
    }

    fetchEnd() {
        if (this.offset != this.byteView.length) {
            throw new Error('Fetch end with non-empty buffer');
        }
        return true;
    }
}

//https://core.telegram.org/mtproto/transports#uri-format
class Transport {
    constructor(options) {
        options = options || {};
        this.isHttps = options.mode || false;
        this.host = options.host || 'web.telegram.org';
        this.port = options.port || (this.isHttps ? 443 : 80);
        this.chosenServers = {};
        this.isTest = options.test || false;
        this.isSubdomain = options.sub || false;

        this.dcOptions = [
            {id: 1, subdomain: 'flora'  },
            {id: 2, subdomain: 'venus'  },
            {id: 3, subdomain: 'aurora' },
            {id: 4, subdomain: 'vesta'  },
            {id: 5, subdomain: 'flora'  }
        ];

        this.publicKeysPem = [
            "-----BEGIN RSA PUBLIC KEY-----MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daSan9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTwEfzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3nSlv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB-----END RSA PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAruw2yP/BCcsJliRoW5eBVBVle9dtjJw+OYED160Wybum9SXtBBLXriwt4rROd9csv0t0OHCaTmRqBcQ0J8fxhN6/cpR1GWgOZRUAiQxoMnlt0R93LCX/j1dnVa/gVbCjdSxpbrfY2g2L4frzjJvdl84Kd9ORYjDEAyFnEA7dD556OptgLQQ2e2iVNq8NZLYTzLp5YpOdO1doK+ttrltggTCy5SrKeLoCPPbOgGsdxJxyz5KKcZnSLj16yE5HvJQn0CNpRdENvRUXe6tBP78O39oJ8BTHp9oIjd6XWXAsp2CvK45Ol8wFXGF710w9lwCGNbmNxNYhtIkdqfsEcwR5JwIDAQAB-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvfLHfYH2r9R70w8prHblWt/nDkh+XkgpflqQVcnAfSuTtO05lNPspQmL8Y2XjVT4t8cT6xAkdgfmmvnvRPOOKPi0OfJXoRVylFzAQG/j83u5K3kRLbae7fLccVhKZhY46lvsueI1hQdLgNV9n1cQ3TDS2pQOCtovG4eDl9wacrXOJTG2990VjgnIKNA0UMoP+KF03qzryqIt3oTvZq03DyWdGK+AZjgBLaDKSnC6qD2cFY81UryRWOab8zKkWAnhw2kFpcqhI0jdV5QaSCExvnsjVaX0Y1N0870931/5Jb9ICe4nweZ9kSDF/gip3kWLG0o8XQpChDfyvsqB9OLV/wIDAQAB-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/ditzm+mPND6xkhzwFIz6J/968CtkcSE/7Z2qAJiXbmZ3UDJPGrzqTDHkO30R8VeRM/Kz2f4nR05GIFiITl4bEjvpy7xqRDspJcCFIOcyXm8abVDhF+th6knSU0yLtNKuQVP6voMrnt9MV1X92LGZQLgdHZbPQz0Z5qIpaKhdyA8DEvWWvSUwwc+yi1/gGaybwlzZwqXYoPOhwMebzKUk0xW14htcJrRrq+PXXQbRzTMynseCoPIoke0dtCodbA3qQxQovE16q9zz4Otv2k4j63cz53J+mhkVWAeWxVGI0lltJmWtEYK6er8VqqWot3nqmWMXogrgRLggv/NbbooQIDAQAB-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvmpxVY7ld/8DAjz6F6q05shjg8/4p6047bn6/m8yPy1RBsvIyvuDuGnP/RzPEhzXQ9UJ5Ynmh2XJZgHoE9xbnfxL5BXHplJhMtADXKM9bWB11PU1Eioc3+AXBB8QiNFBn2XI5UkO5hPhbb9mJpjA9Uhw8EdfqJP8QetVsI/xrCEbwEXe0xvifRLJbY08/Gp66KpQvy7g8w7VB8wlgePexW3pT13Ap6vuC+mQuJPyiHvSxjEKHgqePji9NP3tJUFQjcECqcm0yV7/2d0t/pbCm+ZH1sadZspQCEPPrtbkQBlvHb4OLiIWPGHKSMeRFvp3IWcmdJqXahxLCUS1Eh6MAQIDAQAB-----END PUBLIC KEY-----"
        ];

        this.publicKeysParsed = {};
        this.lastMessageID = [0,0];
        this.timeOffset = 0;
        this.cached = {};
    }

    chooseServer(dcID, upload) {
        if (this.chosenServers[dcID] === undefined) {

            if(this.isSubdomain && !this.dcOptions.hasOwnProperty(dcID - 1)){
                throw new Error("chooseServer: incorrect subdomain ID");
            }

            let chosenServer = this.isHttps ? 'https://' : 'http://';
                chosenServer += this.isSubdomain ? (this.dcOptions[dcID - 1].subdomain + (upload ? '-1' : '') + ".") : "";
                chosenServer += this.host;
                chosenServer += this.port != 80 ? ":" + this.port : "";
                chosenServer += this.isTest ? '/apiw_test1' : '/apiw1';

                this.chosenServers[dcID] = chosenServer;
        }

        return this.chosenServers[dcID];
    }

    async prepareRsaKeys() {
        for(let indx = 0; indx < this.publicKeysPem.length; ++indx) {
            let el = this.publicKeysPem[indx];
            const header = indx ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN RSA PUBLIC KEY-----";
            const footer = indx ? "-----END PUBLIC KEY-----" : "-----END RSA PUBLIC KEY-----";

            let mod = CryptoUtils.hexStringFromPem(el,header,footer);
            let exp = '010001';

            var RSAPublicKey = new BinData();
            RSAPublicKey.storeBytes(CryptoUtils.hexStringToBuffer(mod));
            RSAPublicKey.storeBytes(CryptoUtils.hexStringToBuffer(exp));

            var buffer = RSAPublicKey.tbuffer;

            var fingerprintBytes = await CryptoAlgorithm.sha1(buffer);
            fingerprintBytes = new Uint8Array(fingerprintBytes.slice(-8));
            fingerprintBytes.reverse();

            this.publicKeysParsed[CryptoUtils.bufferToHexString(fingerprintBytes)] = {
                modulus: mod,
                exponent: exp
            }            
        }
    }

    selectRsaKeyByFingerPrint(fingerprints) {
        var foundKey;
        for (let i = 0; i < fingerprints.length; i++) {
            let fingerprintHex = CryptoUtils.bufferToHexString(fingerprints[i]);
            if (foundKey = this.publicKeysParsed[fingerprintHex]) {
                return Object.assign({fingerprint: fingerprints[i]}, foundKey);
            }
        }

        return false;
    }

    generateMessageID (){
        let timeTicks = CryptoUtils.tsNow(),
            timeSec = Math.floor(timeTicks / 1000) + this.timeOffset,
            timeMSec = timeTicks % 1000,
            random = CryptoUtils.nextRandomInt(0xFFFF);

        let messageID = [timeSec, (timeMSec << 21) | (random << 3) | 4]
        if (this.lastMessageID[0] > messageID[0] || this.lastMessageID[0] == messageID[0] && this.lastMessageID[1] >= messageID[1]) {
            messageID = [this.lastMessageID[0], this.lastMessageID[1] + 4];
        }

        this.lastMessageID = messageID;

        return (new Uint32Array(messageID)).buffer;
    }

    applyServerTime (serverTime, localTime) {
        let newTimeOffset = serverTime - Math.floor((localTime || CryptoUtils.tsNow()) / 1000);
        var changed = Math.abs(this.timeOffset - newTimeOffset) > 10;

        this.lastMessageID = [0, 0];
        this.timeOffset = newTimeOffset;
        return changed;
    }

    fetch(url,data) {
        return new Promise((resolve,reject)=>{
            var oReq = new XMLHttpRequest();
            oReq.open("POST", url, true);
            oReq.responseType = "arraybuffer";

            oReq.onload = function (oEvent) {
              resolve(oReq.response);
            };

            oReq.onerror = function(e) {
              reject(e);
            };

            oReq.send(data);            
        });
    }

    mtpAuth(dcID) {
        if (this.cached[dcID] !== undefined) {
            return this.cached[dcID];
        }

        this.chooseServer(dcID);

        var auth = {
            dcID: dcID,
            nonce: CryptoUtils.addPadding([],16)
        };

        return mtpSendReqPQ(auth);
    }

    mtpSendPlainRequest (dcID, requestBuffer) {
        var requestLength = requestBuffer.byteLength,
            requestArray = new Int32Array(requestBuffer);
    
        var header = new BinData()
            header.storeLong((new Uint32Array([0,0])).buffer); // 'auth_key_id'
            header.storeLong(this.generateMessageID());
            header.storeInt(requestLength);
    
        var headerBuffer = header.tbuffer,
            headerArray = new Int32Array(headerBuffer);
        var headerLength = headerBuffer.byteLength;
    
        var resultBuffer = new ArrayBuffer(headerLength + requestLength),
            resultArray = new Int32Array(resultBuffer)
    
        resultArray.set(headerArray)
        resultArray.set(requestArray, headerArray.length)
    
        var requestData = resultArray;
        var url = this.chooseServer(dcID)

        return this.fetch(url, resultArray).then((buffer)=>{
            var deserializer = new BinData(buffer);
            var auth_key_id = deserializer.fetchLong();
            var msg_id = deserializer.fetchLong();
            var msg_len = deserializer.fetchInt();  

            console.log(`Message: ${msg_id}, auth_key_id: ${auth_key_id}, msg_len: ${msg_len}`);
            return deserializer;        
        },(e)=>{
            console.error(e);
        });
    }

    mtpSendReqPQ (auth) {
        var request = new BinData();
        request.storeMethod('req_pq', {nonce: auth.nonce},window.Tgm.MTProto)

        mtpSendPlainRequest(auth.dcID, request.tbuffer).then(function (deserializer) {
        var response = deserializer.fetchObject();

            //   if (response._ != 'resPQ') {
            //     throw new Error('[MT] resPQ response invalid: ' + response._)
            //   }

            //   if (!bytesCmp(auth.nonce, response.nonce)) {
            //     throw new Error('[MT] resPQ nonce mismatch')
            //   }

            //   auth.serverNonce = response.server_nonce
            //   auth.pq = response.pq
            //   auth.fingerprints = response.server_public_key_fingerprints

            //   console.log(dT(), 'Got ResPQ', bytesToHex(auth.serverNonce), bytesToHex(auth.pq), auth.fingerprints)

            //   auth.publicKey = MtpRsaKeysManager.select(auth.fingerprints)

            //   if (!auth.publicKey) {
            //     throw new Error('[MT] No public key found')
            //   }

            //   console.log(dT(), 'PQ factorization start', auth.pq)
            //   CryptoWorker.factorize(auth.pq).then(function (pAndQ) {
            //     auth.p = pAndQ[0]
            //     auth.q = pAndQ[1]
            //     console.log(dT(), 'PQ factorization done', pAndQ[2])
            //     mtpSendReqDhParams(auth)
            //   }, function (error) {
            //     console.log('Worker error', error, error.stack)
            //     deferred.reject(error)
            //   })
            // }, function (error) {
            //   console.error(dT(), 'req_pq error', error.message)
            //   deferred.reject(error)
        });

        // $timeout(function () {
        //   MtpRsaKeysManager.prepare()
        // })
    }
}

class MTProtoUnitTest {
    constructor() {}

    static storeReqPQTest() {
        console.log(`MTProtoUnitTest::storeReqPQTest()`); 

        let auth_key_id = (new Uint32Array([0,0])).buffer;
        let message_id = "51e57ac42770964a";
        let message_length = 20;
        let nonce = "3E0549828CCA27E966B301A48FECE2FC";

        let header = new BinData();
            header.storeLong(auth_key_id); // 'auth_key_id'
            header.storeLong(CryptoUtils.hexStringToBuffer(message_id));
            header.storeInt(message_length);

        let request = new BinData();
            request.storeMethod('req_pq', {nonce: CryptoUtils.hexStringToBuffer(nonce)},window.Tgm.MTProto);
    
        let headerBuffer = header.tbuffer,
            headerArray = new Int32Array(headerBuffer);
        let headerLength = headerBuffer.byteLength;
        let requestLength = request.tbuffer.byteLength;
    
        let resultBuffer = new ArrayBuffer(headerLength + requestLength),
            resultArray = new Int32Array(resultBuffer);

        resultArray.set(headerArray)
        resultArray.set(new Int32Array(request.tbuffer), headerArray.length);

        let str = CryptoUtils.bufferToHexString(resultBuffer);  
        let etal = ("00000000000000004A967027C47AE55114000000789746603E0549828CCA27E966B301A48FECE2FC").toLowerCase();
 
        if(etal != str) {
            console.error(`Assert: ${str} != ${etal}`);
            console.error(`MTProtoUnitTest::storeReqPQTest() -- failed!`);
            return;
        } 

        console.log(`MTProtoUnitTest::storeReqPQTest() -- ok!`); 
    }

    static fetchResPQTest() {
        console.log(`MTProtoUnitTest::fetchResPQTest()`); 

        var deserializer = new BinData({buffer:CryptoUtils.hexStringToBuffer("000000000000000001C8831EC97AE55140000000632416053E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5739073300817ED48941A08F98100000015C4B51C01000000216BE86C022BB4C3")});
        var dauth_key_id = CryptoUtils.bufferToHexString(deserializer.fetchLong());
        var dmsg_id = CryptoUtils.bufferToHexString(deserializer.fetchLong());
        var dmsg_len = deserializer.fetchInt(); 
        var dobj = deserializer.fetchObject('ResPQ',window.Tgm.MTProto);
        var dnonce = CryptoUtils.bufferToHexString(dobj.nonce);
        var dpq = CryptoUtils.bufferToHexString(dobj.pq);
        var dserver_nonce = CryptoUtils.bufferToHexString(dobj.server_nonce);
        var dserver_public_key_fingerprints = CryptoUtils.bufferToHexString(dobj.server_public_key_fingerprints[0]);  

        var tauth_key_id = "0000000000000000";
        var tmsg_id = ("51E57AC91E83C801").toLowerCase();
        var tmsg_len = 64; 
        var tpq = ("17ED48941A08F981").toLowerCase();
        var tnonce = ("3E0549828CCA27E966B301A48FECE2FC").toLowerCase();
        var tserver_nonce = ("A5CF4D33F4A11EA877BA4AA573907330").toLowerCase();
        var tserver_public_key_fingerprints = ("c3b42b026ce86b21").toLowerCase();
        
        console.log(dauth_key_id,dmsg_id,dmsg_len,dobj) 

        if(dauth_key_id != tauth_key_id ||
            dmsg_id != tmsg_id ||
            dmsg_len != tmsg_len ||
            dnonce != tnonce ||
            dpq != tpq ||
            dserver_nonce != tserver_nonce ||
            dserver_public_key_fingerprints != tserver_public_key_fingerprints){

            console.error(`Assert auth_key_id: ${dauth_key_id} != ${tauth_key_id}`);
            console.error(`Assert msg_id: ${dmsg_id} != ${tmsg_id}`);
            console.error(`Assert msg_len: ${dmsg_len} != ${tmsg_len}`);
            console.error(`Assert nonce: ${dnonce} != ${tnonce}`);
            console.error(`Assert pq: ${dpq} != ${tpq}`);
            console.error(`Assert server_nonce: ${dserver_nonce} != ${tserver_nonce}`);
            console.error(`Assert fingerprints: ${dserver_public_key_fingerprints} != ${tserver_public_key_fingerprints}`);
            console.error(`MTProtoUnitTest::fetchResPQTest() -- failed!`);
            return;            
        } 

        console.log(`MTProtoUnitTest::fetchResPQTest() -- ok!`);         
    }

    static pqFactorizeTest(debug) {
        console.log(`MTProtoUnitTest::pqFactorizeTest()`); 

        let pq = CryptoUtils.hexStringToBuffer("17ED48941A08F981");

        let [r1,r2] = NumericUtils.factorize(new Uint8Array(pq),1,debug); 

        let p = r1;
        let q = r2;

        if(NumericUtils.cmp(r2,r1) == -1) {
            p = r2;
            q = r1;
        }

        q = CryptoUtils.bufferToHexString(new Uint8Array(q),true); 
        p = CryptoUtils.bufferToHexString(new Uint8Array(p),true);
        let res1 = ("494C553B").toLowerCase();
        let res2 = ("53911073").toLowerCase();
        
        
        console.log("result:", p, q," == ", res1, res2);

        if(res1 != p || res2 != q) {
           console.error(`Assert: ${p} != ${res1}`);
           console.error(`Assert: ${q} != ${res2}`);
           console.error(`MTProtoUnitTest::pqFactorizeTest() -- failed!`);
           return;
        } 

        console.log(`MTProtoUnitTest::pqFactorizeTest() -- ok!`); 
    }

    static async encryptedDataGenerationUnitTest(auth){
        var data = new BinData();
        data.storeObject({
            _: 'p_q_inner_data',
            pq: auth.pq,
            p: auth.p,
            q: auth.q,
            nonce: auth.nonce,
            server_nonce: auth.server_nonce,
            new_nonce: auth.new_nonce
        },'P_Q_inner_data',window.Tgm.MTProto);

        var dataWithHash = await CryptoAlgorithm.sha1a(data.tbuffer);
        dataWithHash = dataWithHash.concat(data.tbytes);

        // console.log(CryptoUtils.bufferToHexString(dataWithHash));

        let encData = await CryptoAlgorithm.rsaEncrypt(auth.public_key, dataWithHash);

        // console.log(auth,CryptoUtils.bufferToHexString(encData));

        var request = new BinData()
        request.storeMethod('req_DH_params', {
            nonce: auth.nonce,
            server_nonce: auth.server_nonce,
            p: auth.p,
            q: auth.q,
            public_key_fingerprint: auth.public_key.fingerprint,
            encrypted_data: encData
        },window.Tgm.MTProto);

        let auth_key_id = (new Uint32Array([0,0])).buffer;
        let message_id = "51e57ac917717a27";
        let message_length = 320;
        let nonce = "3E0549828CCA27E966B301A48FECE2FC";

        let header = new BinData();
            header.storeLong(auth_key_id); // 'auth_key_id'
            header.storeLong(CryptoUtils.hexStringToBuffer(message_id));
            header.storeInt(message_length);
    
        let headerBuffer = header.tbuffer,
            headerArray = new Int32Array(headerBuffer);
        let headerLength = headerBuffer.byteLength;
        let requestLength = request.tbuffer.byteLength;
    
        let resultBuffer = new ArrayBuffer(headerLength + requestLength),
            resultArray = new Int32Array(resultBuffer);

        resultArray.set(headerArray)
        resultArray.set(new Int32Array(request.tbuffer), headerArray.length);

        let str = CryptoUtils.bufferToHexString(resultBuffer); 
        console.log(str); 
    }

    static async serverDHParamsTest(auth,tr) {
        console.log(`MTProtoUnitTest::serverDHParamsTest()`); 

        var response = new BinData({buffer:CryptoUtils.hexStringToBuffer("000000000000000001544336CB7AE551780200005C07E8D03E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA573907330FE50020028A92FE20173B347A8BB324B5FAB2667C9A8BBCE6468D5B509A4CBDDC186240AC912CF7006AF8926DE606A2E74C0493CAA57741E6C82451F54D3E068F5CCC49B4444124B9666FFB405AAB564A3D01E67F6E912867C8D20D9882707DC330B17B4E0DD57CB53BFAAFA9EF5BE76AE6C1B9B6C51E2D6502A47C883095C46C81E3BE25F62427B585488BB3BF239213BF48EB8FE34C9A026CC8413934043974DB03556633038392CECB51F94824E140B98637730A4BE79A8F9DAFA39BAE81E1095849EA4C83467C92A3A17D997817C8A7AC61C3FF414DA37B7D66E949C0AEC858F048224210FCC61F11C3A910B431CCBD104CCCC8DC6D29D4A5D133BE639A4C32BBFF153E63ACA3AC52F2E4709B8AE01844B142C1EE89D075D64F69A399FEB04E656FE3675A6F8F412078F3D0B58DA15311C1A9F8E53B3CD6BB5572C294904B726D0BE337E2E21977DA26DD6E33270251C2CA29DFCC70227F0755F84CFDA9AC4B8DD5F84F1D1EB36BA45CDDC70444D8C213E4BD8F63B8AB95A2D0B4180DC91283DC063ACFB92D6A4E407CDE7C8C69689F77A007441D4A6A8384B666502D9B77FC68B5B43CC607E60A146223E110FCB43BC3C942EF981930CDC4A1D310C0B64D5E55D308D863251AB90502C3E46CC599E886A927CDA963B9EB16CE62603B68529EE98F9F5206419E03FB458EC4BD9454AA8F6BA777573CC54B328895B1DF25EAD9FB4CD5198EE022B2B81F388D281D5E5BC580107CA01A50665C32B552715F335FD76264FAD00DDD5AE45B94832AC79CE7C511D194BC42B70EFA850BB15C2012C5215CABFE97CE66B8D8734D0EE759A638AF013")});
        var dauth_key_id = CryptoUtils.bufferToHexString(response.fetchLong());
        var dmsg_id = CryptoUtils.bufferToHexString(response.fetchLong());
        var dmsg_len = response.fetchInt(); 
        response = response.fetchObject('Server_DH_Params',window.Tgm.MTProto);
        console.log(response);

        if (response._ != 'server_DH_params_fail' && response._ != 'server_DH_params_ok') {
            throw new Error('[MT] Server_DH_Params response invalid: ' + response._);
        }

        if (NumericUtils.cmp(auth.nonce, response.nonce) != 0) {
            throw new Error('[MT] Server_DH_Params nonce mismatch');
        }

        if (NumericUtils.cmp(auth.server_nonce, response.server_nonce) != 0) {
            new Error('[MT] Server_DH_Params server_nonce mismatch');
        }

        if (response._ == 'server_DH_params_fail') {
            var newNonceHash = (await CryptoAlgorithm.sha1a(auth.new_nonce)).slice(-16)
            if (NumericUtils.cmp(newNonceHash, response.new_nonce_hash) != 0) {
                throw new Error('[MT] server_DH_params_fail new_nonce_hash mismatch');
            }
            throw new Error('[MT] server_DH_params_fail');
        }

        auth.local_time = CryptoUtils.tsNow();
        auth.tmp_aes_key = (await CryptoAlgorithm.sha1a(auth.new_nonce.concat(auth.server_nonce)))
                            .concat((await CryptoAlgorithm.sha1a(auth.server_nonce.concat(auth.new_nonce))).slice(0, 12));
        auth.tmp_aes_iv = (await CryptoAlgorithm.sha1a(auth.server_nonce.concat(auth.new_nonce))).slice(12)
                            .concat(await CryptoAlgorithm.sha1a([].concat(auth.new_nonce, auth.new_nonce)), auth.new_nonce.slice(0, 4));

        auth.aes = CryptoAlgorithm.getAesIgeWrapper(auth.tmp_aes_key,auth.tmp_aes_iv);

        var answerWithHash = await CryptoAlgorithm.aesIgeDecrypt(auth.aes, response.encrypted_answer);

        var hash = CryptoUtils.cloneArray(new Uint8Array(answerWithHash.slice(0, 20)));
        var answerWithPadding = answerWithHash.slice(20);

        var deserializer = new BinData({buffer:answerWithPadding});
        var response = deserializer.fetchObject('Server_DH_inner_data',window.Tgm.MTProto);

        if (response._ != 'server_DH_inner_data') {
            throw new Error('[MT] server_DH_inner_data response invalid');
        }

        if (NumericUtils.cmp(auth.nonce, response.nonce) != 0) {
            throw new Error('[MT] server_DH_inner_data nonce mismatch');
        }

        if (NumericUtils.cmp(auth.server_nonce, response.server_nonce) != 0) {
            throw new Error('[MT] server_DH_inner_data serverNonce mismatch');
        }

        auth.g = response.g
        auth.dh_prime = response.dh_prime
        auth.g_a = response.g_a
        auth.server_time = response.server_time
        auth.retry = 0

        //mtpVerifyDhParams(auth.g, auth.dhPrime, auth.gA)

        var offset = deserializer.offset;

        if (NumericUtils.cmp(hash, await CryptoAlgorithm.sha1a(answerWithPadding.slice(0, offset))) != 0) {
            throw new Error('[MT] server_DH_inner_data SHA1-hash mismatch');
        }

        tr.applyServerTime(auth.server_time, auth.local_time)

        console.log(auth)

        let dh_prime = ("C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B").toLowerCase();
        let g_a = ("262AABA621CC4DF587DC94CF8252258C0B9337DFB47545A49CDD5C9B8EAE7236C6CADC40B24E88590F1CC2CC762EBF1CF11DCC0B393CAAD6CEE4EE5848001C73ACBB1D127E4CB93072AA3D1C8151B6FB6AA6124B7CD782EAF981BDCFCE9D7A00E423BD9D194E8AF78EF6501F415522E44522281C79D906DDB79C72E9C63D83FB2A940FF779DFB5F2FD786FB4AD71C9F08CF48758E534E9815F634F1E3A80A5E1C2AF210C5AB762755AD4B2126DFA61A77FA9DA967D65DFD0AFB5CDF26C4D4E1A88B180F4E0D0B45BA1484F95CB2712B50BF3F5968D9D55C99C0FB9FB67BFF56D7D4481B634514FBA3488C4CDA2FC0659990E8E868B28632875A9AA703BCDCE8F").toLowerCase();
        let server_time = 1373993675;
        let g = 2;

        if(CryptoUtils.bufferToHexString(auth.dh_prime) != dh_prime ||
            CryptoUtils.bufferToHexString(auth.g_a) != g_a ||
            auth.server_time != server_time ||
            auth.g != g){

            console.error(`Assert dh_prime: ${CryptoUtils.bufferToHexString(auth.dh_prime)} != ${dh_prime}`);
            console.error(`Assert g_a: ${CryptoUtils.bufferToHexString(auth.g_a)} != ${g_a}`);
            console.error(`Assert server_time: ${auth.server_time} != ${server_time}`);
            console.error(`Assert g: ${auth.g} != ${g}`);
            console.error(`MTProtoUnitTest::serverDHParamsTest() -- failed!`);
            return;            
        } 

        console.log(`MTProtoUnitTest::serverDHParamsTest() -- ok!`);   
    }

    static verifyDhParamsTest(auth) {
        console.log(`MTProtoUnitTest::verifyDhParams()`);

        let dhPrimeHex = CryptoUtils.bufferToHexString(auth.dh_prime);

        if (auth.g > 7 || auth.g < 2 ||
            dhPrimeHex !== 'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b') {
            // The verified value is from https://core.telegram.org/mtproto/security_guidelines
            throw new Error('[MT] DH params are not verified: unknown dhPrime');
        }

        let [_dh_prime_1,c] = NumericUtils.sub(auth.dh_prime,[1]);

        if (NumericUtils.cmp(auth.g_a,[1]) <= 0) {
            throw new Error('[MT] DH params are not verified: gA <= 1')
        }

        if (NumericUtils.cmp(auth.g_a,_dh_prime_1) >= 0) {
            throw new Error('[MT] DH params are not verified: gA >= dhPrime - 1')
        }
        
        let _2pow2048_64 = CryptoUtils.hexStringToArray("10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let [_dh_prime_2pow2048_64,c1] = NumericUtils.sub(auth.dh_prime,_2pow2048_64);

        if (NumericUtils.cmp(auth.g_a, _2pow2048_64) < 0) {
            throw new Error('[MT] DH params are not verified: gA < 2^{2048-64}')
        }
        if (NumericUtils.cmp(auth.g_a, _dh_prime_2pow2048_64) > 0) {
            throw new Error('[MT] DH params are not verified: gA > dhPrime - 2^{2048-64}')
        }

        console.log(`MTProtoUnitTest::verifyDhParams() -- ok!`);

        return true
    }

    static async clientDHParamsRequestTest(auth) {
        console.log(`MTProtoUnitTest::clientDHParamsRequestTest()`);

        let g = CryptoUtils.hexStringToArray(auth.g.toString(16),true);

        auth.b = CryptoUtils.hexStringToArray("6F620AFA575C9233EB4C014110A7BCAF49464F798A18A0981FEA1E05E8DA67D9681E0FD6DF0EDF0272AE3492451A84502F2EFC0DA18741A5FB80BD82296919A70FAA6D07CBBBCA2037EA7D3E327B61D585ED3373EE0553A91CBD29B01FA9A89D479CA53D57BDE3A76FBD922A923A0A38B922C1D0701F53FF52D7EA9217080163A64901E766EB6A0F20BC391B64B9D1DD2CD13A7D0C946A3A7DF8CEC9E2236446F646C42CFE2B60A2A8D776E56C8D7519B08B88ED0970E10D12A8C9E355D765F2B7BBB7B4CA9360083435523CB0D57D2B106FD14F94B4EEE79D8AC131CA56AD389C84FE279716F8124A543337FB9EA3D988EC5FA63D90A4BA3970E7A39E5C0DE5");
        auth.g_b = NumericUtils.modPow(g,auth.b,auth.dh_prime);

        // console.log(auth)
        if(CryptoUtils.bufferToHexString(auth.g_b) != ("73700E7BFC7AEEC828EB8E0DCC04D09A0DD56A1B4B35F72F0B55FCE7DB7EBB72D7C33C5D4AA59E1C74D09B01AE536B318CFED436AFDB15FE9EB4C70D7F0CB14E46DBBDE9053A64304361EB358A9BB32E9D5C2843FE87248B89C3F066A7D5876D61657ACC52B0D81CD683B2A0FA93E8ADAB20377877F3BC3369BBF57B10F5B589E65A9C27490F30A0C70FFCFD3453F5B379C1B9727A573CFFDCA8D23C721B135B92E529B1CDD2F7ABD4F34DAC4BE1EEAF60993DDE8ED45890E4F47C26F2C0B2E037BB502739C8824F2A99E2B1E7E416583417CC79A8807A4BDAC6A5E9805D4F6186C37D66F6988C9F9C752896F3D34D25529263FAF2670A09B2A59CE35264511F").toLowerCase()) {
            console.error(`MTProtoUnitTest::clientDHParamsRequestTest() -- failed!`);
            return;              
        }

        var data = new BinData();
        data.storeObject({
          _: 'client_DH_inner_data',
          nonce: auth.nonce,
          server_nonce: auth.server_nonce,
          retry_id: CryptoUtils.addPadding(CryptoUtils.hexStringToArray((auth.retry++).toString(16),true),8,true,"s"),
          g_b: auth.g_b
        }, 'Client_DH_Inner_Data',window.Tgm.MTProto);

        let dataWithHash = await CryptoAlgorithm.sha1a(data.tbuffer);
        dataWithHash = dataWithHash.concat(data.tbytes);

        // console.log(CryptoUtils.bufferToHexString(dataWithHash));

        let encryptedData = await CryptoAlgorithm.aesIgeEncrypt(auth.aes, dataWithHash);

        // console.log(CryptoUtils.bufferToHexString(encryptedData));

        let request = new BinData();
        request.storeMethod('set_client_DH_params', {
          nonce: auth.nonce,
          server_nonce: auth.server_nonce,
          encrypted_data: encryptedData
        },window.Tgm.MTProto)

        let auth_key_id = (new Uint32Array([0,0])).buffer;
        let message_id = "51e57acd2aa32c6d";
        let message_length = 376;
        let nonce = "3E0549828CCA27E966B301A48FECE2FC";

        let header = new BinData();
            header.storeLong(auth_key_id); // 'auth_key_id'
            header.storeLong(CryptoUtils.hexStringToBuffer(message_id));
            header.storeInt(message_length);
    
        let headerBuffer = header.tbuffer,
            headerArray = new Int32Array(headerBuffer);
        let headerLength = headerBuffer.byteLength;
        let requestLength = request.tbuffer.byteLength;
    
        let resultBuffer = new ArrayBuffer(headerLength + requestLength),
            resultArray = new Int32Array(resultBuffer);

        resultArray.set(headerArray)
        resultArray.set(new Int32Array(request.tbuffer), headerArray.length);

        let str = CryptoUtils.bufferToHexString(resultBuffer); 
        console.log(str); 

        console.log(`MTProtoUnitTest::clientDHParamsRequestTest() -- ok!`);
    }

    static async clientDHParamsResponseTest(auth) {
        console.log(`MTProtoUnitTest::clientDHParamsResponseTest()`);

        var response = new BinData({buffer:CryptoUtils.hexStringToBuffer("00000000000000000130AAC5CE7AE5513400000034F7CB3B3E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA573907330CCEBC0217266E1EDEC7FB0A0EED6C220")});
        var dauth_key_id = CryptoUtils.bufferToHexString(response.fetchLong());
        var dmsg_id = CryptoUtils.bufferToHexString(response.fetchLong());
        var dmsg_len = response.fetchInt(); 
        response = response.fetchObject('Set_client_DH_params_answer',window.Tgm.MTProto);
        console.log(response);

        if (response._ != 'dh_gen_ok' && response._ != 'dh_gen_retry' && response._ != 'dh_gen_fail') {
            throw new Error('[MT] Set_client_DH_params_answer response invalid: ' + response._);
        }

        if (NumericUtils.cmp(auth.nonce, response.nonce) != 0) {
            throw new Error('[MT] server_DH_inner_data nonce mismatch');
        }

        if (NumericUtils.cmp(auth.server_nonce, response.server_nonce) != 0) {
            throw new Error('[MT] server_DH_inner_data serverNonce mismatch');
        }

        let auth_key = NumericUtils.modPow(auth.g_a,auth.b,auth.dh_prime);
        let auth_key_hash = await CryptoAlgorithm.sha1a(auth_key);
        let auth_key_aux = auth_key_hash.slice(0, 8);
        let auth_key_ID = auth_key_hash.slice(-8);

        switch (response._) {
          case 'dh_gen_ok':
            var newNonceHash1 = (await CryptoAlgorithm.sha1a(auth.new_nonce.concat([1], auth_key_aux))).slice(-16);

            if (NumericUtils.cmp(newNonceHash1, response.new_nonce_hash1) != 0) {
                throw new Error('[MT] Set_client_DH_params_answer new_nonce_hash1 mismatch');
            }

            if(CryptoUtils.bufferToHexString(newNonceHash1) != ("CCEBC0217266E1EDEC7FB0A0EED6C220").toLowerCase()) {
                console.error(`MTProtoUnitTest::clientDHParamsResponseTest() -- failed!`);
                return;     
            }

            var server_salt = CryptoUtils.xorArrays(auth.new_nonce.slice(0, 8), auth.server_nonce.slice(0, 8));

            auth.auth_key_ID = auth_key_ID;
            auth.auth_key = auth_key;
            auth.server_salt = server_salt;
            break;

          case 'dh_gen_retry':
            var newNonceHash2 = (await CryptoAlgorithm.sha1a(auth.new_nonce.concat([2], auth_key_aux))).slice(-16);
            if (NumericUtils.cmp(newNonceHash2, response.new_nonce_hash2) != 0) {
                throw new Error('[MT] Set_client_DH_params_answer new_nonce_hash2 mismatch');
            }

            console.log("neew dh_gen_retry");
            break;

          case 'dh_gen_fail':
            var newNonceHash3 = (await CryptoAlgorithm.sha1a(auth.new_nonce.concat([3], auth_key_aux))).slice(-16);
            if (NumericUtils.cmp(newNonceHash3, response.new_nonce_hash3) != 0) {
                throw new Error('[MT] Set_client_DH_params_answer new_nonce_hash3 mismatch');
            }

            throw new Error('[MT] Set_client_DH_params_answer fail');
        }     

        console.log(`MTProtoUnitTest::clientDHParamsResponseTest() -- ok!`);
    }

    static async run() {
        MTProtoUnitTest.storeReqPQTest();
        MTProtoUnitTest.fetchResPQTest();
        MTProtoUnitTest.pqFactorizeTest(false);

        let tr = new Transport();
        await tr.prepareRsaKeys();

        let auth = {
            new_nonce: CryptoUtils.hexStringToArray("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"),
            nonce: CryptoUtils.hexStringToArray("3E0549828CCA27E966B301A48FECE2FC"),
            server_nonce: CryptoUtils.hexStringToArray("A5CF4D33F4A11EA877BA4AA573907330"),
            pq: CryptoUtils.hexStringToArray("17ED48941A08F981"),
            p: CryptoUtils.hexStringToArray("494C553B"),
            q: CryptoUtils.hexStringToArray("53911073"),
            public_key: null,
            fingerprints: [CryptoUtils.hexStringToArray("c3b42b026ce86b21")],
        };
        //CryptoUtils.nextRandomArray(auth.new_nonce);

        auth.public_key = tr.selectRsaKeyByFingerPrint(auth.fingerprints);

        await MTProtoUnitTest.encryptedDataGenerationUnitTest(auth);
        await MTProtoUnitTest.serverDHParamsTest(auth,tr);

        auth.g = 2;
        auth.dh_prime = CryptoUtils.hexStringToArray("C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B");
        auth.g_a = CryptoUtils.hexStringToArray("262AABA621CC4DF587DC94CF8252258C0B9337DFB47545A49CDD5C9B8EAE7236C6CADC40B24E88590F1CC2CC762EBF1CF11DCC0B393CAAD6CEE4EE5848001C73ACBB1D127E4CB93072AA3D1C8151B6FB6AA6124B7CD782EAF981BDCFCE9D7A00E423BD9D194E8AF78EF6501F415522E44522281C79D906DDB79C72E9C63D83FB2A940FF779DFB5F2FD786FB4AD71C9F08CF48758E534E9815F634F1E3A80A5E1C2AF210C5AB762755AD4B2126DFA61A77FA9DA967D65DFD0AFB5CDF26C4D4E1A88B180F4E0D0B45BA1484F95CB2712B50BF3F5968D9D55C99C0FB9FB67BFF56D7D4481B634514FBA3488C4CDA2FC0659990E8E868B28632875A9AA703BCDCE8F");
    
        MTProtoUnitTest.verifyDhParamsTest(auth);

        await MTProtoUnitTest.clientDHParamsRequestTest(auth);
        await MTProtoUnitTest.clientDHParamsResponseTest(auth);
    }
}

var tgm = new Tgm();
tgm.attachToWindow();

AESUnitTest.run();
AES_IGEUnitTest.run();
NumericUtilsUnitTest.run();
RSAUnitTest.run();
  
await MTProtoUnitTest.run();