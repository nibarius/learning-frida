Java.perform(function(){

  var MainActivity = Java.use("sg.vantagepoint.uncrackable2.MainActivity");
  MainActivity.a.overload("java.lang.String").implementation = function(s) {
    console.log("Tamper detection suppressed, message was: " + s);
  }

  Java.use("sg.vantagepoint.uncrackable2.MainActivity").onResume.implementation = function() {
    this.onResume();

    // Hook to strncmp and look for any calls to it with the magic word as argument
    var theMagicWord = "12345678901234567890123";
    var strncmp = listNames('libfoo.so', 'strncmp')
    attachToStrncmp(strncmp, theMagicWord);

    // Find the CodeCheck instance that was created by the app in onCreate()
    // Then call it with the magic word as argument.
    Java.choose("sg.vantagepoint.uncrackable2.CodeCheck", {
      onMatch : function(instance) {
        instance.a(Java.use("java.lang.String").$new(theMagicWord));
        return "stop";
      },
      onComplete:function() {}
    });

    // We've got what we wanted, detach again to prevent multiple attachments
    // to strncmp if onResume is called multiple times.
    Interceptor.detachAll();
  }
});

// Attach to strncmp on the given address and log any calls
// made where one of the strings to compare is 'compareTo'
function attachToStrncmp(strncmpAddress, compareTo) {
  Interceptor.attach(strncmpAddress, {
    // strncmp takes 3 arguments, str1, str2, max number of characters to compare
    onEnter: function(args) {
      var len = compareTo.length;
      if (args[2].toInt32() != len) {
        // Definitely comparing something uninteresting, bail.
        return;
      }
      var str1 = args[0].readUtf8String(len)
      var str2 = args[1].readUtf8String(len)
      if (str1 == compareTo || str2 == compareTo) {
        console.log("strncmp(" + str1 + ", " + str2 + ", " + len + ") called");
      }
    },
    // Return value of strncmp is of no interest.
    //onLeave: function(retval) {}
  });
}

// Lists all names (exports, imports and symbols) in the given module
// if a 'needle' is given this function returns the address of the name
// that matches the 'needle'
function listNames(module, needle) {
  var address = undefined;
  console.log("Names found in " + module + ":");
  Process.enumerateModules()
    .filter(function(m){ return m["path"].toLowerCase().indexOf(module) != -1; })
    .forEach(function(mod) {
      mod.enumerateExports().forEach(function (entry) {
        console.log("Export: " + entry.name );
        if (entry.name.indexOf(needle) != -1) address = entry.address;
      });
      mod.enumerateImports().forEach(function (entry) {
        console.log("Import: " + entry.name );
        if (entry.name.indexOf(needle) != -1) address = entry.address;
      });
      mod.enumerateSymbols().forEach(function (entry) {
        console.log("symbol name: " + entry.name );
        if (entry.name.indexOf(needle) != -1) address = entry.address;
      });
    });
  console.log("");
  return address;
}
