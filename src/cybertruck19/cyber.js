Java.perform(function(){
  console.log("");
  bypassHookDetection();
  challenge1();
  challenge2();
  challenge3();
});

function bypassHookDetection() {
  var HookDetector = Java.use("org.nowsecure.cybertruck.detections.HookDetector");
  HookDetector.isFridaServerInDevice.implementation = function() {
    console.log("Frida detection bypassed");
    return false;
  }
}

function challenge1() {
  var Challenge1 = Java.use('org.nowsecure.cybertruck.keygenerators.Challenge1');
  Challenge1.generateDynamicKey.implementation = function(bArr) {
    var ret = this.generateDynamicKey(bArr);
    console.log("Challenge 1 key: " + toHexString(ret));
    return ret;
  }
}

function challenge2() {
  var Challenge2 = Java.use('org.nowsecure.cybertruck.keygenerators.a');
  Challenge2.a.overload('[B', '[B').implementation = function(bArr1, bArr2) {
    var ret = this.a(bArr1, bArr2);
    console.log("Challenge 2 key: " + toHexString(ret));
    return ret;
  }
}

function challenge3() {
  var MainActivity = Java.use('org.nowsecure.cybertruck.MainActivity');
  MainActivity.k.implementation = function() {
    // Setup the native interceptors
    nativeChallenge3();
    this.k();
  }
}

function nativeChallenge3() {
  // Detach all to prevent duplicate attachments when the script is reloaded.
  Interceptor.detachAll();

  Interceptor.attach(Module.findExportByName("libnative-lib.so", "Java_org_nowsecure_cybertruck_MainActivity_init"), {
    onEnter: function(args) {
      // The init functions calls strlen to check the length of the key, attach to it
      this.strlen = Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
        onEnter: function(args) {
          // strln is only of interest when actually called from libnative-lib.so
          if (isAddressInModule('libnative-lib.so', this.returnAddress)) {
            console.log("Challenge 3 key: "+ args[0].readUtf8String(32));
          }
        }
      });


    },
    onLeave: function(retval) {
      // Detach from strlen since we no longer need to listen to it.
      this.strlen.detach();

      // the init function de-obfuscates the secret and stores it in a local variable
      // (on the stack). The stack grows towards lower addresses, so look at the content
      // of the stack before the stack pointer when returning from the init function.
      console.log('Content of the stack when returning from the init function:');
      console.log(hexdump(this.context.sp.sub(208), {offset: 0, length: 208, header: true, ansi:true}));
    }
  });
}

// Checks if the given address is located inside the given module
function isAddressInModule(moduleName, address) {
  var module = Process.findModuleByName(moduleName)
  return address >= module.base && address < module.base.add(module.size);
}

// Converts a Frida Java byte array to a hex string.
function toHexString(byteArray) {
  var ret = ""
  // byteArray is a Java array, not a javascript array so things like foreach
  // and Array.from doesn't work
  for (var i = 0; i < byteArray.length; i++) {
    // Frida's Java byte array uses signed bytes, do bitwise & to convert to a signed byte
    // Then convert to a string with a leading zero, and take the last two characters
    // to always get exactly two characters for each byte.
    ret += ('0' + (byteArray[i] & 0xFF).toString(16)).slice(-2)
  }
  return ret;
}
