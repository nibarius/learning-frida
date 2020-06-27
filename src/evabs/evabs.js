Java.perform(function(){
  var Launch = Java.use("com.revo.evabs.Launch");
  Launch.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
    this.onCreate(bundle);
    var f = Java.use("com.revo.evabs.Frida1").$new();
    console.log("Frida: '" + f.stringFromJNI() + "'");
    var debugMe = Java.use("com.revo.evabs.DebugMe").$new();
    console.log("debugMe: 'EVABS{" + debugMe.stringFromJNI() + "}'");
  }
});


