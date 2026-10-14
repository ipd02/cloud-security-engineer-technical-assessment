// Probe of API behaviour that changes between the vulnerable and fixed versions.
// No database or network is used. Run from a directory where the packages are installed
// with: npm ci --ignore-scripts
// The jsonwebtoken part runs on any version. The mongoose part is skipped if mongoose is absent.
const jwt=require('jsonwebtoken');
const t=(n,f)=>{try{const r=f();console.log(n,'=> OK',typeof r==='string'?r.slice(0,30):typeof r)}catch(e){console.log(n,'=> THROWS',e.name+': '+e.message.slice(0,140))}};
const tok=jwt.sign({a:1},'secret');
t('verify HS256 default',()=>jwt.verify(tok,'secret').a);
t('verify with alg none token',()=>jwt.verify(jwt.sign({a:1},null,{algorithm:'none'}),'secret'));
t('sign RSA 1024 key',()=>{const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('rsa',{modulusLength:1024});return jwt.sign({a:1},k.privateKey.export({type:'pkcs1',format:'pem'}),{algorithm:'RS256'})});
t('sign RSA 2048 key',()=>{const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('rsa',{modulusLength:2048});return jwt.sign({a:1},k.privateKey.export({type:'pkcs1',format:'pem'}),{algorithm:'RS256'})});
t('verify with public key but HS256 token (alg confusion)',()=>{const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('rsa',{modulusLength:2048});const pub=k.publicKey.export({type:'spki',format:'pem'});return jwt.verify(jwt.sign({a:1},pub),pub)});
t('sign EC key with RS256 (key type check)',()=>{const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('ec',{namedCurve:'prime256v1'});return jwt.sign({a:1},k.privateKey.export({type:'pkcs8',format:'pem'}),{algorithm:'RS256'})});
t('sign RSA 1024 key with allowInsecureKeySizes',()=>{const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('rsa',{modulusLength:1024});return jwt.sign({a:1},k.privateKey.export({type:'pkcs1',format:'pem'}),{algorithm:'RS256',allowInsecureKeySizes:true})});
t('sign with no secret',()=>jwt.sign({a:1},''));
t('sign expiresIn "1x"',()=>jwt.sign({a:1},'s',{expiresIn:'1x'}));
t('sign payload string + expiresIn',()=>jwt.sign('str','s',{expiresIn:60}));
let m;try{m=require('mongoose')}catch(e){console.log('mongoose not installed, skipping');process.exit(0)}
console.log('mongoose',m.version);
const M=m.model('T',new m.Schema({a:Number}));
t('Model.find with callback',()=>M.find({},()=>{}));
t('Model.findOne with callback',()=>M.findOne({},()=>{}));
let rejected=false;const sv=new M({a:1}).save(()=>{});if(sv&&sv.catch)sv.catch((e)=>{rejected=true;console.log('doc.save with callback => REJECTS',e.name+': '+e.message)});
setTimeout(()=>{if(!rejected)console.log('doc.save with callback => not rejected (no database, so the save is only queued)');process.exit(0)},300);
t('Model.count()',()=>M.count({}));
t('Model.update()',()=>M.update({}, {a:1}));
t('Model.remove()',()=>M.remove({}));
