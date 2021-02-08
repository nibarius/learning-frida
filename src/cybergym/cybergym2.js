Java.perform(function(){
  Java.use("ja").a.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
    var ret = this.a(a, b);
    console.log("flag: " + ret);
    return ret;
  };
});