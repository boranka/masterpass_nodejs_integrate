const aesjs = require('aes-js');
const hmacsha1 = require('hmacsha1');

function getToken(input){
    console.log(input);
    const datetime = new Date().toISOString()
    .replace(/T/, '')
    .replace(/\..+/, '')
    .replace(/:/, '')
    .replace(/:/, '')
    .replace(/-/, '')
    .replace(/-/, '');

    const referenceNumber = Math.floor(new Date().getTime() / 1000);
    var referemceNumberLen = referenceNumber.length;
    const userId = input.userId;
    const is3DSecure = input.SecureStatus;

    if(referemceNumberLen < 10){
        referemceNumberLen = '0'+referemceNumberLen;
    }

    var msisdn = input.mobile_phone;

    msisdn = createValidMsidn(msisdn);
    var clientID = getConfig('clientID');
    var data = 'FF01' + specPadLen(clientID) + specToBHex(clientID) +
    'FF02' + '01' + getTimezone() +
    'FF03' + specPadLen(datetime) + specToBHex(datetime) + 
    'FF04' + specPadLen(msisdn) + specToBHex(msisdn) +
    'FF05' + specPadLen(referenceNumber) + specToBHex(referenceNumber) +
    'FF06' + specPadLen(userId) + specToBHex(userId) + 
    'FF07' + '0101' + '';   
    var validationType = '00';
    if(is3DSecure == true){
        validationType = '04';
    }
    data = data + 'FF08' + '01' + validationType;

    if(data.length % 32 != 0){
        data = data + '8';
        const padC = Math.ceil(data.length/32)*32;
        data = data.padEnd(padC, 0); 
    }

    var key = Buffer.from(getConfig('encryptionKey'), 'hex');

    var iv = new Buffer.alloc(16);
    var textBytes = Buffer.from(data,'hex');
    
    var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    var encryptedBytes = aesCbc.encrypt(textBytes);
    
    var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes).toUpperCase();

    var hash = hmacsha1(getConfig('macKey'), encryptedHex);
    var macKey = Buffer.from(hash, 'base64').toString('hex').toUpperCase();
    macKey = macKey;

    var token = encryptedHex + macKey;
    return  {"token": token, "referenceNumber": referenceNumber, "macroMerchantID": getConfig('macroMerchantID')};
}

function getTimezone(){
    var dt = new Date();
    //dt.setHours( dt.getHours() + 3 );
    var diff1 = (-dt.getTimezoneOffset() < 0 ? '-' : '+') + (Math.abs(dt.getTimezoneOffset() / 60) < 10 ? '0' : '') + (Math.abs(dt.getTimezoneOffset() / 60));
    var diff2 = ':00';
    var p =  diff1+diff2;

    var dif = diff1;
    var f = dif.substr(0,1);
    var s = dif.substr(1);
    var rTime = '';

    if(f == '-'){
        rTime = '8';
    }else{
        rTime = '0';
    }

    rTime = rTime + s;
    var ret = { 
        'hex' : rTime,
        'dif' : dif
        };

    return s;
}

function dechex(str){
    hexString = str.toString(16).toUpperCase();
    return hexString;
}

function createValidMsidn(msisdn){
    var ret = msisdn.replace(/[^0-9\.]+/g, '');
    
    if(ret.substr(0,2) == '00'){
        ret = ret.substr(2);
    }else if(ret.substr(0,1) == '0'){
        ret = ret.substr(1);
    }

    if(ret.length == 10){
        return '90' + ret;
    }
    return ret;
}

function getConfig(type){
    var arrConf = {
        'clientID'                  : 'xxx',
        'macroMerchantID'           : 'xxx',
        'encryptionKey'             : 'xxx',
        'macKey'                    : 'xxx',
        //'macKey'                  : 'xxx',
        'vpos_currency_code'        : 'TRY',
        'vpos_merchant_id'          : '0', 
        'vpos_merchant_terminal_id' : '0', 
        'vpos_merchant_email'       : 'vpos@domain.com', //merchant mail adresiniz.
        'vpos_terminal_user_id'     : '0', /
        'vpos_store_key'            : '0', 
        'vpos_posnet_id'            : '0', 
        'acquirer_ica'              : '0', 
    };

    return arrConf[type];
}


function specToBHex(str) {
     let bufStr = Buffer.from(str.toString(), 'utf8');
     var ret =  bufStr.toString('hex');
     return ret;

}

function specPadLen(str) {

    var len = str.toString().length;
    var dLen = dechex(len).toString().toUpperCase();
    var pad = 0;
    if(len>9){
        pad = '';
    }
    var dLen2 = formatted_string(0,dLen,'l');  
        
    return dLen2;
}

function formatted_string(pad,user_str, pad_pos)
{
    
    var ret;
  if (typeof user_str === 'undefined') 
    ret =  pad;
  if (pad_pos == 'l')
     {
     ret =  (pad + user_str).slice(-pad.length);
     }
  else 
    {
    ret =  (user_str + pad).substring(0, pad.length);
    }
    return ret;
}

function validStr(str){
    var charMap = {
        Ç: 'C',
        Ö: 'O',
        Ş: 'S',
        İ: 'I',
        I: 'i',
        Ü: 'U',
        Ğ: 'G',
        ç: 'c',
        ö: 'o',
        ş: 's',
        ı: 'i',
        ü: 'u',
        ğ: 'g'
      };
      if(str === null){
        return 'Bulunmuyor';
      }else{
        str_array = str.split('');
    
        for (var i = 0, len = str_array.length; i < len; i++) {
            str_array[i] = charMap[str_array[i]] || str_array[i];
        }
    
        str = str_array.join('');
    
        var clearStr = str.replace(" ", "").replace("-", "").replace(/[^a-z0-9-.çöşüğı]/gi, "");

        return clearStr;
    }
}

  Date.prototype.addHours= function(h){
    this.setHours(this.getHours()+h);
    return this;
    };

function getServices(service){
    var urs = {
        'TEST' : {
            'generateKey'    : 'https://test.masterpassturkiye.com/MMIUIMasterPass_V2/MerchantServices/MPGGenerateKeyService.asmx?wsdl',
            'commitPurchase' : 'https://test.masterpassturkiye.com/MMIUIMasterPass_V2/MerchantServices/MPGCommitPurchaseService.asmx?wsdl',
            'refund'         : 'https://test.masterpassturkiye.com/MMIUIMasterPass_V2/MerchantServices/MPGMerchantTransactionRefundService.asmx?wsdl',
            'void'           : 'https://test.masterpassturkiye.com/MMIUIMasterPass_V2/MerchantServices/MPGMerchantTransactionVoidService.asmx?wsdl',
            'clientSideUrl'  : 'https://test.masterpassturkiye.com/MasterpassJsonServerHandler/v2'
        },
        'UAT' :{
            'generateKey'    : 'https://uatmmi.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGGenerateKeyService.asmx?wsdl',
            'commitPurchase' : 'https://uatmmi.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGCommitPurchaseService.asmx?wsdl',
            'refund'         : 'https://uatmmi.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGMerchantTransactionRefundService.asmx?wsdl',
            'void'           : 'https://uatmmi.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGMerchantTransactionVoidService.asmx?wsdl',
            'clientSideUrl'  : 'https://uatui.masterpassturkiye.com/v2'
        },
        'PROD' :{
            'generateKey'    : 'https://prod.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGGenerateKeyService.asmx?wsdl',
            'commitPurchase' : 'https://prod.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGCommitPurchaseService.asmx',
            'refund'         : 'https://prod.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGMerchantTransactionRefundService.asmx',
            'void'           : 'https://prod.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGMerchantTransactionVoidService.asmx',
            'clientSideUrl'  : 'https://ui.masterpassturkiye.com/v2'
        }
    };
    return urs['PROD'][service];
}




