// for version 1.1.12
Java.perform(function(){
  // Response manipulation part. Just check what the hash is of my input and make sure to respond with the same
  var otp = Java.use('com.hpandro.androidsecurity.ui.activity.task.authentication.responseMani.ResponseManipOTPActivity');
  otp.otpToSHA1.implementation = function(a) {
    var ret = this.otpToSHA1(a);
    console.log("input: " + a + " return: " + ret);
    return ret;
  }
})
