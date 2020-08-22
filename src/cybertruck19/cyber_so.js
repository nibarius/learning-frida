Java.perform(function(){
  console.log("");
  bypassHookDetection();
  challenge3();
});

function bypassHookDetection() {
  var HookDetector = Java.use("org.nowsecure.cybertruck.detections.HookDetector");
  HookDetector.isFridaServerInDevice.implementation = function() {
    console.log("Frida detection bypassed");
    return false;
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
  const SECRET_LENGTH = 32;
  

  /*var hook1 = Interceptor.attach(Module.findBaseAddress('libnative-lib.so').add(0x72b), {
    onEnter: function(args) {
      console.log("hook 1");
      hook1.detach();
    }
  });
  // intercepting two addresses directly after each other lead to a crash
  var hook2 = Interceptor.attach(Module.findBaseAddress('libnative-lib.so').add(0x768), {
    onEnter: function(args) {
      console.log("hook 2");
      hook2.detach();
    }
  });*/
  var rightOne = false;
  Interceptor.attach(Module.findExportByName("libnative-lib.so", "Java_org_nowsecure_cybertruck_MainActivity_init"), {
    onEnter: function(args) {
      // The init functions calls strlen to check the length of the key, attach to it
      var mystrlen = Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
        onEnter: function(args) {
          // strln is only of interest when actually called from libnative-lib.so
          if (isAddressInModule('libnative-lib.so', this.returnAddress)) {
            console.log("in strncmp, args: " + JSON.stringify(args[0]));
            console.log("Challenge 3 key: "+ args[0].readUtf8String(32));
            rightOne = true;
          }
        },
        onLeave: function(retval) {
          if (rightOne) {
            console.log("retval for strlen: " + retval);
            mystrlen.detach();
          }
        }
      });
    }
  });
}

// Checks if the given address is located inside the given module
function isAddressInModule(moduleName, address) {
  var module = Process.findModuleByName(moduleName)
  return address >= module.base && address < module.base.add(module.size);
}
