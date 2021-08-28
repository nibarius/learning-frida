// version 1.1.14
Java.perform(function(){
  
  // Just brute force the pin
  var bd6 = Java.use("com.hpandro.androidsecurity.ui.activity.task.misc.Backdoor6Activity");
  bd6.hello.implementation = function(a) { 
    console.log("hello called with " + a );
    var ret = "NO";
    for (let i = 0; i <= 9999; i++) {
      ret = this.hello(("000" + i).substr(-4,4));
      if (ret != "NO") {
        console.log("correct pin found at: " + i); //4321
        break;
      }
    }
    return ret;
  }
  
});