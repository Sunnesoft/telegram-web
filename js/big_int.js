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

    static bufferToUintArray(buffer,blockSize) {
    	buffer = new DataView(buffer);
    	let length = buffer.byteLength;
    	let n = Math.ceil(length/blockSize);
    	var w = [];

    	for(let i = 0; i<n; ++i) {
    		switch(blockSize) {
				case 1: w.push(buffer.getUint8(i)); break;
				case 2: w.push(buffer.getUint16(i*2,false)); break;
				case 4: w.push(buffer.getUint32(i*4,false)); break;
    		}
    	}

		switch(blockSize) {
			case 1: return new Uint8Array(w);
			case 2: return new Uint16Array(w);
			case 4: return new Uint32Array(w);
		}
    }
}

class CryptoBigInt {
	constructor(v){
		v = v || {};
		v.sign = v.sign || 0;

		this.buffer = v.val;

		console.log(v)

		if(this.buffer instanceof ArrayBuffer) {
			this.buffer = this.buffer.slice();
		}

        if(typeof this.buffer == "string" || 
        	this.buffer instanceof String) {
        	if(this.buffer.length < 1) {
        		throw new Error("CryptoBigInt::constructor(): input is empty string!")
        	}

        	switch(this.buffer[0]) {
        		case "-": 
        			this.sign = -1;
        			this.buffer = this.buffer.substr(1, this.buffer.length-1);
        			break;
        		case "+":
        			this.sign = 0;
        			this.buffer = this.buffer.substr(1, this.buffer.length-1);
        			break;  
        		default:
        			this.sign = 0;      			
        	}

        	if(this.buffer.length < 1) {
        		throw new Error("CryptoBigInt::constructor(): input is empty string!")
        	}

        	v.padStart = v.padStart || true;
            this.buffer = CryptoUtils.hexStringToBuffer(this.buffer, v.padStart);           
        } 

        if(this.buffer instanceof Uint16Array ||
        	this.buffer instanceof Uint8Array || 
        	this.buffer instanceof Uint32Array) {
            this.buffer = this.buffer.buffer.slice(); 
            this.sign = v.sign;         
        } 

        if(this.buffer instanceof Array) {
        	v.bits = v.bits || 8;
        	switch(v.bits) {
        		case 8 : this.buffer = new Uint8Array(this.buffer).buffer.slice(); break;
        		case 16 : this.buffer = new Uint16Array(this.buffer).buffer.slice(); break;
        		case 32 : this.buffer = new Uint32Array(this.buffer).buffer.slice(); break;
        	}
            this.sign = v.sign;         	
        } 

        console.log(this.buffer)

        // this.buffer = new Uint8Array(CryptoUtils.addPadding(new Uint8Array(this.buffer),4,true,"s")).buffer;

		this.a8 = CryptoUtils.bufferToUintArray(this.buffer,1);
		this.a16 = CryptoUtils.bufferToUintArray(this.buffer,2);
		this.a32 = CryptoUtils.bufferToUintArray(this.buffer,4);  

		console.log(this)    
	}

	clone() {
		return new CryptoBigInt({val:this.buffer,sign:this.sign});
	}

	arr(x,index) {
		if(x.length <= index) {
			return 0;
		}

		return x[x.length - index - 1];
	}

	radix(bit) {
		switch(bit) {
			case 8 :
				return 0xff + 1;
			case 16 :
				return 0xffff + 1;
			case 32 :
				return 0xffffffff + 1;
			default: 
				throw new Error("CryptoBigInt::radix() incorrect 'bit' value")
		}
	}

	inverse() {
		this.sign = this.sign == 0 ? -1 : 0;
		return this;
	}

    //HAC 14.7
    static adds(h,g, debug = false) {
    	let bit = 32;
    	let x = h["a"+bit];
    	let y = g["a"+bit];
        let b = h.radix(bit);
        let n = x.length - 1;
        let t = y.length - 1; 
        n = n > t ? n : t;

        var w = new Array(n + 2);
        let c = 0;

        debug && console.log("mpAdd",x,y);

        for(let i = 0; i <= n; ++i) {
            debug && console.log(`${h.arr(x,i)} + ${g.arr(y,i)} + ${c}`);
            let d = h.arr(x,i) + g.arr(y,i) + c;
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

        w = new CryptoBigInt({val:w.reverse(),sign:0,bits:bit});
        debug && console.log(w);
        return w;
    }

    //HAC 14.9
    static subs(h,g, debug = false) {
    	let bit = 32;
    	let x = h["a"+bit];
    	let y = g["a"+bit];
        let b = h.radix(bit);
        let n = x.length - 1;
        let t = y.length - 1; 
        n = n > t ? n : t;

        var w = new Array(n + 1);
        let c = 0;

        debug && console.log("mpSub",x,y);

        for(let i = 0; i <= n; ++i) { 
            debug && console.log(`${b} + ${h.arr(x,i)} - ${g.arr(y,i)} + ${c}`); 
            let d = h.arr(x,i) - g.arr(y,i) + c;
            if(d >= 0) { 
                c = 0;
            } else {
                d += b;
                c = -1;
            } 
            w[i] = d % b;
            debug && console.log(d,w[i],c);
        }

        w = new CryptoBigInt({val:w.reverse(),sign:c,bits:bit});

        if(c == -1 && g.sign == 0) {
            return CryptoBigInt.subs(new CryptoBigInt({
            	val: (new Array(n + 1).fill(0)),
            	bits: bit,
            	sign: 0
            }),w,debug);
        } 
        debug && console.log(w,c);
        return w;        
    }

    add(g,debug){
    	let x = this;
    	let y = g;
    	let sx = x.sign;
    	let sy = y.sign;

        if(sx == 0 && sy == 0) {
            return CryptoBigInt.adds(x,y,debug);
        }

        if(sx == 0 && sy == -1) {
            return CryptoBigInt.subs(x,y,debug);
        }

        if(sx == -1 && sy == 0) {
            return CryptoBigInt.subs(y,x,debug);
        }

        if(sx == -1 && sy == -1) {
            return CryptoBigInt.adds(x,y,debug).inverse();
        }       
    }

    sub(g,debug){
    	let x = this;
    	let y = g;
    	let sx = x.sign;
    	let sy = y.sign;

        if(sx == 0 && sy == 0) {
            return CryptoBigInt.subs(x,y,debug);
        }

        if(sx == 0 && sy == -1) {
            return CryptoBigInt.adds(x,y,debug);
        }

        if(sx == -1 && sy == 0) {
            return CryptoBigInt.adds(x,y,debug).inverse();
        }

        if(sx == -1 && sy == -1) {
            return CryptoBigInt.subs(y,x,debug);
        }       
    }

    toString() {
    	return CryptoUtils.bufferToHexString(this.buffer,true); 
    }
}

class UnitTest {
	constructor() {
		this.queue = [];
	}

	registerAction(func,input) {
		this.queue.push(new Promise((resolve,reject)=>{
			func(input,resolve,reject);
		}));
	}

	run() {
		Promise.all(this.queue).then(value => { 
			console.log(value);
		}, reason => {
			console.log(reason);
		});
	}
}

var unittest = new UnitTest();
unittest.registerAction((input,resolve,reject)=>{
	let x = new CryptoBigInt({val:input.a});
	let y = new CryptoBigInt({val:input.b});
	let z = x.add(y,true).toString();
	if(z == input.res) {
		resolve(`"CryptoBigInt::add() ${z} == ${input.res}`);
	}
	else {
		reject(`CryptoBigInt::add() ${z} != ${input.res}`);
	}
},{a:"0024fa92",b:"22042b0",res:"2453d42"});

// unittest.registerAction((input,resolve,reject)=>{
// 	let x = new CryptoBigInt(input.a);
// 	let y = new CryptoBigInt(input.b);
// 	let z = x.sub(y).toString();
// 	if(z == input.res) {
// 		resolve("CryptoBigInt::sub()");
// 	}
// 	else {
// 		reject("CryptoBigInt::sub()",z,input.res);
// 	}
// },{a:"24fa92",b:"22042b0",res:"2453d42"});

// unittest.registerAction((input,resolve,reject)=>{
// 	let x = new CryptoBigInt(input.a);
// 	let y = new CryptoBigInt(input.b);
// 	let z = x.add(y).toString();
// 	if(z == input.res) {
// 		resolve("CryptoBigInt::add()");
// 	}
// 	else {
// 		reject("CryptoBigInt::add()",z,input.res);
// 	}
// },{a:"24fa92",b:"22042b0",res:"2453d42"});

//         NumericUtilsUnitTest.mpSubTest(3996879,4637923,641044,false);
//         NumericUtilsUnitTest.mpSubTest(1255453466,342345,1255111121,false);

unittest.run();
