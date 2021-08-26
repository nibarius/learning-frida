Java.perform(function(){
 
  // IMSI level:
  var intrinsics = Java.use('kotlin.jvm.internal.Intrinsics');
  intrinsics.areEqual.overload('java.lang.Object', 'java.lang.Object').implementation = function(a, b){
    if (b.toString() == "431337133713373") {
      return true;
    }
    return this.areEqual(a, b);
  }

  
  var ctx = Java.use("android.content.Context");
  ctx.getSystemService.overload('java.lang.String').implementation = function(str) {
    console.log("calling getSystemService");
    return this.getSystemService(str);
  }
  
  var tm = Java.use('android.telephony.TelephonyManager');
  tm.getSubscriberId.overload().implementation = function() {
    console.log("calling getSubscriberId");
    return "431337133713373";
  }
  tm.getSubscriberId.overload('int').implementation = function(i) {
    console.log("calling getSubscriberId: " + i);
    return "431337133713373";
  }
  
  var secure = Java.use('android.provider.Settings$Secure');
  secure.getString.implementation = function(context, id) {
    console.log("called with: " + id);
    if (id == "android_id") {
      return "131337133713373";
    }
    return this.getString(context, id);
  }
  
  var wifi = Java.use('android.net.wifi.WifiInfo');
  wifi.getMacAddress.implementation = function() {
    return "01:02:03:04:05:06";
  };
  
 
  var macLevel = Java.use('com.hpandro.androidsecurity.ui.activity.task.deviceID.DeviceMacTaskActivity');
  macLevel.showFlag.implementation = function(flag) {
    console.log("Flag: " + flag);
    this.showFlag(flag);
  }
  
  var loc = Java.use('android.location.Location');
  Java.use('android.location.Location').getLatitude.implementation = function() {
    return 29.9791;
  };  /* strange, can't do both at the same time, will cause the app to crash
  Java.use('android.location.Location').getLongitude.implementation = function() {
    return 31.1341;
  };*/
  
  Java.use('com.hpandro.androidsecurity.ui.activity.task.deviceID.GPSLocationTaskActivity').showFlag.implementation = function(flag) {
    console.log("Flag: " + flag);
    this.showFlag(flag);
  }
  
});