Java.perform(function(){
  Java.use("java.lang.String").equalsIgnoreCase.implementation = function(a) {
    if (this == "5555") {
      console.log("Real passcode was: " + a);
      return true;
    }
    return this.equalsIgnoreCase(a);
  };
});