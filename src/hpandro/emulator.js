// version 1.1.15
Java.perform(function(){
 
  var emu = Java.use('com.hpandro.androidsecurity.utils.emulatorDetection.EmulatorDetector');
  emu.log.implementation = function(s) { console.log("Logging: " + s); }
  emu.checkFiles.implementation = function(a, b){ return false }
  emu.checkIp.implementation = function(){ return false }
  emu.isDebug.implementation = function(){ return false }
  emu.checkOperatorNameAndroid.implementation = function(){ return false }
  emu.checkPhoneNumber.implementation = function(){ return false }
  emu.checkBasic.implementation = function(){ return false }
  
  // Can't open the correct level for Emulator package check and QEMU, pressing the task button does nothing at all.
  var lastMenuName = "";
  var act = Java.use('com.hpandro.androidsecurity.utils.fragment.HomeWebViewFragment');
  act.redirectToTask.implementation = function() {
    this.redirectToTask();
    console.log("redirect to task called");
    // The redirect to task button doesn't link to the Package name task activity, it just doesn't do anything
    // We have to open the activity ourselves instead.
    // Find the HomeWebViewFragment instance and start call startActivity on it with the appropriate class
    // when the task button is pressed.
    Java.choose('com.hpandro.androidsecurity.utils.fragment.HomeWebViewFragment', {
      onMatch: function(instance) {
        var activity = instance.getActivity();
        var targetClass = null;
        if (lastMenuName == "Check Package Name") {
          targetClass = Java.use('com.hpandro.androidsecurity.ui.activity.task.emulatorDetection.PackageNamesActivity');
        }
        else if (lastMenuName == "QEMU") {
          targetClass = Java.use('com.hpandro.androidsecurity.ui.activity.task.emulatorDetection.QEMUDetectionActivity');
        }

        if (activity != null && targetClass != null) {
          var intent = Java.use('android.content.Intent').$new(activity, targetClass.class);
          console.log("intent: " + JSON.stringify(activity));
          instance.startActivity(intent);
        }
      },
      onComplete: function() {}
    });
  }
  
  // Note having the code below active on startup can cause the app to crash,
  // comment it out during startup, or just load the script after startup instead.
  
  // Keep track of which menu entry that has been last pressed and use that as an indication
  // of which task is currently open.
  Java.use('com.hpandro.androidsecurity.ui.menu.MenuModel').getMenuName.implementation = function() {
    var ret = this.getMenuName();  
    lastMenuName = ret;
    return ret;
  }
});