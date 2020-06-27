Java.perform(function(){

  const secretLength = 24;
  var xorkey = undefined;

  // libc.strstr == libfoo.strstr since it's imported by libfoo. But
  // libfoo has not been loaded when the script is loaded so we can't hook it
  // trying to hook it after it has been loaded is too late since it will
  // detect frida and exit right away when loaded. So hook libc instead
  Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function(args) {
      this.fridaDetected = 0;
      if (args[0].readUtf8String().indexOf("frida") != -1) {
        this.fridaDetected = 1;
      }
      else {
        this.fridaDetected = 0;
      }

    },
    onLeave: function(retval) {
      if (this.fridaDetected == 1) {
        retval.replace(0);
      }
    }
  });

  Interceptor.attach(Module.findExportByName("libc.so", "strncpy"), {
    onEnter: function(args) {
      if (args[2].toInt32() == secretLength) {
        xorkey = new Uint8Array(args[1].readByteArray(secretLength));
      }
    },
  });

  var MainActivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
  MainActivity.$init.implementation = function() {
      this.$init();
      attachToSecretGenerator();
  };

  MainActivity.onResume.implementation = function() {
      this.onResume();
      // Find the CodeCheck instance that was created by the app in onCreate()
      // Then call it with a dummy string.
      Java.choose("sg.vantagepoint.uncrackable3.CodeCheck", {
        onMatch : function(instance) {
          instance.check_code(Java.use("java.lang.String").$new("dummy"));
          return "stop";
        },
        onComplete:function() {}
      });
  };

  MainActivity.showDialog.implementation = function(s) {
    console.log("Tamper detection suppressed, message was: " + s);
  }

  function attachToSecretGenerator() {
    // function that generates the secret code is located at 0x12c0
    Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0x12c0), {
      onEnter: function(args) {
        // First (only) argument is the address of where the secret should be stored
        this.answerLocation = args[0];
      },
      onLeave: function(retval) {
        var encodedAnswer = new Uint8Array(this.answerLocation.readByteArray(secretLength));
        var decodedAnswer = xorByteArrays(encodedAnswer, xorkey);
        console.log("Secret key: " + String.fromCharCode.apply(null, decodedAnswer));
      }
    });
  }

  function xorByteArrays(a1, a2) {
    var i;
    const ret = new Uint8Array(new ArrayBuffer(a2.byteLength));
    for (i = 0; i < a2.byteLength; i++) {
      ret[i] = a1[i] ^ a2[i];
    }
    return ret;
  }
});


