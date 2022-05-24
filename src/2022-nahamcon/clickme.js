Java.perform(function(){
  var ma = Java.use("com.example.clickme.MainActivity");
  ma.getFlagButtonClick.implementation = function(view){
    this.CLICKS.value = 99999999;
    this.getFlagButtonClick(view);
  }
});