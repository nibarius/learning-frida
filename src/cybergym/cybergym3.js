Java.perform(function(){
  Java.use("java.lang.String").getBytes.overload('java.lang.String').implementation= function(a) {
    console.log("getBytes called on: " + this);
    return this.getBytes(a);
  };
});