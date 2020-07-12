Java.perform(function(){
  var WebAppInterface = Java.use("com.hacker101.oauth.WebAppInterface");
  var flag = WebAppInterface.$new(null).getFlagPath();
  console.log("Flag path: " + flag);
});
