Java.perform(function(){
  var bin = Java.use("com.hpandro.androidsecurity.ui.activity.task.binary.NativeFunTaskActivity");
  bin.hello.implementation = function() { 
    var ret = this.flag();
    console.log("flag: " + ret);
    return ret;
  }
});