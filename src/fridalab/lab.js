Java.perform(function(){
  let lab = Java.use("uk.rossmarks.fridalab.MainActivity");
  // Pretend to solve everything:
  /*lab.changeColors.implementation = function() {
    this.completeArr.value = Java.array('int', [1, 1, 1, 1, 1, 1, 1, 1]);
    this.changeColors();
  }*/
  
  // Challenge 1. Change challenge_01's variable chall01 to 1
  Java.use("uk.rossmarks.fridalab.challenge_01").chall01.value = 1;
  
  // Challenge 2. Call chall02()
  Java.choose("uk.rossmarks.fridalab.MainActivity", {
      onMatch : function(instance) {
        instance.chall02();
        return "stop";
      },
      onComplete:function() {}
    });
    
  // Challenge 3. Change return value of chall03
  Java.use("uk.rossmarks.fridalab.MainActivity").chall03.implementation = function(){
    return true;
  };
  
  // Challenge 4. Call chall04 with the argument "frida"
  Java.choose("uk.rossmarks.fridalab.MainActivity", {
    onMatch : function(instance) {
      instance.chall04("frida");
      return "stop";
    },
    onComplete:function() {}
  });
    
  // Challenge 5. Change argument of chall05
  Java.use("uk.rossmarks.fridalab.MainActivity").chall05.implementation = function(a){
    this.chall05("frida");
  };
  
  // Challenge 6. Call chall06 with the correct value (changed every 50ms)
  Java.use("uk.rossmarks.fridalab.MainActivity").changeColors.implementation = function() {
    this.chall06(Java.use("uk.rossmarks.fridalab.challenge_06").chall06.value);
    this.changeColors();
  }
  
  // Challenge 7. Brute force a pin code
  // Cheat and just check what the pin is instead of brute forcing it
  //console.log("the pin code is: " + Java.use("uk.rossmarks.fridalab.challenge_07").chall07.value);
  let pin = ""
  for (let i = 1000; i < 10000; i++) {
    pin = "" + i;
    if (Java.use("uk.rossmarks.fridalab.challenge_07").check07Pin(pin)) {
      break;
    }
  }
  Java.choose("uk.rossmarks.fridalab.MainActivity", {
    onMatch : function(instance) {
      instance.chall07(pin);
      return "stop";
    },
    onComplete:function() {}
  });
  
  // Challenge 8. Change the text of the button
  Java.choose("uk.rossmarks.fridalab.MainActivity", {
    onMatch : function(instance) {
      let button = instance.findViewById(2131165231);
      let casted = Java.cast(button, Java.use('android.support.v7.widget.AppCompatButton'));
      let text = Java.use('java.lang.String').$new('Confirm');
      casted.setText(text);

      return "stop";
    },
    onComplete:function() {}
  });
});
