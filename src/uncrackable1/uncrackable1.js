Java.perform(function(){

  // Convert a byte array to a string
  // https://reverseengineering.stackexchange.com/a/22255
  function bufferToString(buf) {
    var buffer = Java.array('byte', buf);
    var result = "";
    for(var i = 0; i < buffer.length; ++i){
      result += (String.fromCharCode(buffer[i] & 0xff));
    }
    return result;
  }

  // If root / debuggable app is detected this method is called which shows an error
  // message to the user and then exit. Replace the method with one that does nothing.
  Java.use("sg.vantagepoint.uncrackable1.MainActivity").a.implementation=function(s){
    console.log("Tamper detection suppressed, message was: " + s);
  }

  // Automatically find the secret when onResume is called
  Java.use("sg.vantagepoint.uncrackable1.MainActivity").onResume.implementation = function() {
    this.onResume();
    Java.use("sg.vantagepoint.uncrackable1.a").a("dummy");
  }

  // The secret is encrypted. When the user inputs a string the correct one
  // is decrypted and compared with the provided one. This method returns
  // the decrypted version so a comparison can be made. Print the decrypted
  // secret that is returned.
  Java.use("sg.vantagepoint.a.a").a.implementation=function(ba1, ba2){
    const retval = this.a(ba1, ba2);
    console.log("secret code is: " + bufferToString(retval));
    return retval;
  }

});
