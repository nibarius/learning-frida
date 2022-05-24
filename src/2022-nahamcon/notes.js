Java.perform(function(){
  let success = false;
  let toTry;
  // Hook the method that decrypts the data for convenient access to the input
  // and output files. It throws an exception if decryption fails.
  Java.use("o.d").k.implementation = function(pin, input, output) {  
    let start = 5000;
    let offset = 0;
    success = false;
    console.log("Starting pin brute force attempt");
    // Assume that the correct pin is near the middle and iterate outwards
    while (Math.abs(offset) <= 5000) {
      toTry = String(start + offset).padStart(4, '0');
      let nextPin = "" + toTry + toTry + toTry + toTry;
      try {
        this.k(nextPin, input, output);
        if (success) {
          return;
        }
      } catch (ex) {}
      offset = nextOffset(offset);
    }
  }
  
  // Successful decryption isn't enough. Many pins can decrypt the data
  // without having exceptions being thrown, but for all pins except the
  // correct one the data is just garbage. So need to check if the data
  // is json data when the data is written to disk just after decryption.
  let fos = Java.use("java.io.FileOutputStream");
  fos.write.overload('[B').implementation = function(barr) {
    if (barr[0] == 0x7b) {
      // 0x7b is ascii code for '{' which json files start with
      console.log("Pin: " + toTry + " - Correct pin found");
      this.write(barr);
      success = true;
    } else {
      console.log("Pin: " + toTry + " - Decryption succeeded but resulted in garbage");
    }
  }
});

// Calculate next offset to iterate from the middle and out.
// Returns a number of opposite sign and increases the absolute value when input is positive
function nextOffset(offset) {
  if (offset >= 0) {
    offset++;
  }
  return offset * -1;
}
