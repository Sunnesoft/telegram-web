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

NumericUtilsUnitTest.run();