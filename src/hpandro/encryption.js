// version 1.1.12
Java.perform(function(){
 
  var rsa = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.RSAActivity');
  rsa.decrypt.implementation = function(a, b) {
    var decrypted = this.decrypt(a, b);
    console.log("Decrypted: " + Java.use('java.lang.String').$new(decrypted));
    return decrypted;
  }
  
  var des = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.DESTaskActivity');
  des.decrypt.implementation = function(a) {
    var decrypted = this.decrypt(a);
    console.log("Decrypted: " + decrypted);
    return decrypted;
  }
  
  var des3 = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.ThreeDESActivity');
  des3.decrypt.implementation = function(a, b) {
    var decrypted = this.decrypt(a, b);
    console.log("Decrypted: " + decrypted);
    return decrypted;
  }
  
  var rc4 = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.RC4Activity');
  rc4.decrypt.implementation = function(a) {
    var decrypted = this.decrypt(a);
    console.log("Decrypted: " + Java.use('java.lang.String').$new(decrypted));
    return decrypted;
  }
  
  var blowfish = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.BlowfishActivity');
  blowfish.decrypt.implementation = function(a) {
    var decrypted = this.decrypt(a);
    console.log("Decrypted: " + decrypted);
    return decrypted;
  }
  
  var aes = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.AESActivity');
  aes.decrypt.overload('java.lang.String', 'java.lang.String', '[B').implementation = function(a, b, c) {
    var decrypted = this.decrypt(a, b, c);
    console.log("Decrypted: " + Java.use('java.lang.String').$new(decrypted));
    return decrypted;
  }
  
  var iv = Java.use('com.hpandro.androidsecurity.ui.activity.task.encryption.PredictableInitializationVectorActivity');
  iv.decrypt.overload('java.lang.String', 'java.lang.String', '[B').implementation = function(a, b, c) {
    var decrypted = this.decrypt(a, b, c);
    console.log("Decrypted: " + Java.use('java.lang.String').$new(decrypted));
    return decrypted;
  }
 
});