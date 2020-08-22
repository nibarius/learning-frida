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

  // The LEA instruction at 75c loads the address where the key is stored into RDI
  // before the call to strlen. Read the key from this location on the next instruction
  var keyHook = Interceptor.attach(Module.findBaseAddress('libnative-lib.so').add(0x760), {
    onEnter: function(args) {
      console.log("Challenge3 key: " + this.context.rdi.readUtf8String(SECRET_LENGTH));
      keyHook.detach();
    }
  })

  var secret = "";
  var len = 0;
  // Assembly code from where the xor operation takes place
  // address    operation   operands    comment
  // 7bd       XOR          ECX, EDX    ECX = ECX ^ EDX
  // 7bf       MOV          SIL, CL
  var secretHook = Interceptor.attach(Module.findBaseAddress('libnative-lib.so').add(0x7bf), {
    onEnter: function(args) {
      // Only r*x and not e*x is available trough Frida, but e*x is just the 4 lower bytes of
      // r*x, so we can look at r*x instead.
      if (len++ < SECRET_LENGTH) {
        secret += String.fromCharCode(this.context.rcx);
      } else { 
        console.log("Challenge3 secret: " + secret);
        secretHook.detach();
      }
    }
  });
}

