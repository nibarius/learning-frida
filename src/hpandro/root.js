// version 1.1.12

Java.perform(function(){
 
  var root = Java.use('com.hpandro.androidsecurity.utils.rootDetection.RootDetectionUtils$Companion');
  root.checkFlagBusyBoxBinaries.implementation = function() {
    console.log("checking for busybox");
    return false; //make it return true on startup, then update to return false when in the level.
  }
  
  root.checkFlagSUExists.implementation = function() {
    console.log("checking for su exists");
    return false; //make it return true on startup, then update to return false when in the level.
  }
  
  root.checkFlagRWSystems.implementation = function() {
    console.log("checking for checkFlagRWSystems");
    return false; //make it return true on startup, then update to return false when in the level.
  }
  
  root.checkFlagRootManagementApps.implementation = function() {
    console.log("checking for checkFlagRootManagementApps");
    return false; //make it return true on startup, then update to return false when in the level.
  }
  
  /*
  // make it return true on startup, then run the original implementation in the task (app crashes otherwise).
  root.checkFlagRootClockingApps.implementation = function() {
    console.log("checking for checkFlagRootClockingApps");
    return true;
  }*/
 
   root.checkFlagPotentialDangerousApps.implementation = function() {
    console.log("checking for checkFlagPotentialDangerousApps");
    return false; //make it return true on startup, then update to return false when in the level.
  }  
  
  root.checkFlagTestKeys.implementation = function() {
    console.log("checking for checkFlagTestKeys");
    return false; //make it return true on startup, then update to return false when in the level.
  }
 
    //got a crash when running the task first. But not running this function at all on startup, then running it later made it work.
   root.checkFlagDangerousProps.implementation = function() {
    console.log("checking for checkFlagDangerousProps");
    console.log("retval: " + ret);
    return false;
  }
 
});