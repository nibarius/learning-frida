Java.perform(function(){
  let success = false;
  let sb = Java.use('org.libsodium.jni.crypto.SecretBox');
  sb.decrypt.implementation = function (bArr, bArr2) {
    let ret ="";
    try {
      ret = this.decrypt(bArr, bArr2);
      success = true;
      console.log("found the flag: " + Java.use('java.lang.String').$new(ret));
    } catch (ex) {
      success = false;
      ret =  Java.array('byte', []);
    }
    return ret;
  }

  let listener = Java.use('com.hackerone.mobile.challenge2.MainActivity$1');
  listener.onComplete.implementation = function(key) {
    console.log("on complete called with key: " + key);
    for (let i = 999999; i > 0; i--) {
       if (i % 50 == 0) {
        // reset cool down regularly to not have to wait.
        this.this$0.value.resetCoolDown();
      }
      let toTry = String(i).padStart(6, '0');
      let ret = this.onComplete(toTry);
      if (success) {
        console.log("the correct pin is: " + toTry);
        return ret;
      }
    }
    console.log("Done");
  };
});
