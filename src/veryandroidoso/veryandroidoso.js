Java.perform(function() {
  Java.use("ooo.defcon2019.quals.veryandroidoso.MainActivity").onResume.implementation = function() {
    this.onResume();
    var Solver = Java.use("ooo.defcon2019.quals.veryandroidoso.Solver");
    bypassSleep(Solver);
    var flagBytes = solve(Solver);
    console.log("flag: " + getFlag(flagBytes));
  }
});

// Count number of sleep calls to know how many bytes are correct
// see comment for bypassSleep() for more details.
var sleepCount = 0;

// index is 0-8, specifying which parameter to solve
// v is an array of values to use as input to the solver
// returns a list of all acceptable values
function solveByteAt(Solver, index, v) {
  var curr = v[index];
  var acceptable = [];

  // Bytes before the sixth byte sleeps once per byte
  // Byte 6 does not sleep at all (no prior call to scramble)
  // so all bytes after that requires one less sleep.
  var targetSleepCount = index < 5 ? index + 1 : index;
  do {
    v[index] = curr;
    sleepCount = 0;
    Solver.solve(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]);
    if (sleepCount > targetSleepCount) {
      acceptable.push(curr);
    }
  } while (curr++ < 256)
  v[index] = acceptable[0];
  return acceptable;
}

// Solve the last byte by trying all possible combinations of acceptable values
function solveLast(Solver, acceptable) {
  console.log("solving last, this will take a while...");
  for (var a = 0; a < acceptable[0].length; a++) {
    for (var b = 0; b < acceptable[1].length; b++) {
      for (var c = 0; c < acceptable[2].length; c++) {
        for (var d = 0; d < acceptable[3].length; d++) {
          for (var e = 0; e < acceptable[4].length; e++) {
            for (var f = 0; f < acceptable[5].length; f++) {
              for (var g = 0; g < acceptable[6].length; g++) {
                for (var h = 0; h < acceptable[7].length; h++) {
                  for (var i = 0; i < 256; i++) {
                    var ret = Solver.solve(acceptable[0][a], acceptable[1][b], acceptable[2][c],
                    acceptable[3][d], acceptable[4][e], acceptable[5][f], acceptable[6][g],
                    acceptable[7][h], i);
                    if (ret) {
                      var secret = [acceptable[0][a], acceptable[1][b], acceptable[2][c],
                        acceptable[3][d], acceptable[4][e], acceptable[5][f], acceptable[6][g],
                        acceptable[7][h], i];
                      console.log("Secret found: " + secret);
                      return secret;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  console.log("couldn't find the secret :(");
}

function solve(Solver) {
  var params =   [0, 0, 0, 0, 0 ,0, 0, 0, 0];
  var acceptable = [];
  acceptable[0] = solveByteAt(Solver, 0, params);
  console.log("Byte 1 solved: " + acceptable[0]);

  acceptable[1] = solveByteAt(Solver, 1, params);
  console.log("Byte 2 solved: " + acceptable[1]);

  acceptable[2] = solveByteAt(Solver, 2, params);
  console.log("Byte 3 solved: " + acceptable[2]);

  acceptable[3] = solveByteAt(Solver, 3, params);
  console.log("Byte 4 solved: " + acceptable[3]);

  // We detect that byte x is has been solved by counting calls to scramble
  // but byte 6 is solved without any scramble call. This means that both
  // byte 5 and 6 needs to be solved before the next call to scramble is
  // made. So solve byte 6 before 5 to be able to detect when byte 5 is
  // correct.
  var tmp = [];
  for(var i = 0; i < 256; i++) {
    if ((i & 0x41) == 65) {
      tmp.push(i);
    }
  }
  acceptable[5] = tmp;
  params[5] = tmp[0];
  console.log("Byte 6 solved: " + acceptable[5]);

  acceptable[4] = solveByteAt(Solver, 4, params);
  console.log("Byte 5 solved: " + acceptable[4]);

  acceptable[6] = solveByteAt(Solver, 6, params);
  console.log("Byte 7 solved: " + acceptable[6]);

  acceptable[7] = solveByteAt(Solver, 7, params);
  console.log("Byte 8 solved: " + acceptable[7]);

  return solveLast(Solver, acceptable);
}

// Get the flag by converting the array to a hex string
function getFlag(bytes) {
  var ret = "OOO{";
  for(var i = 0; i < bytes.length; i++) {
    ret += ("0" + bytes[i].toString(16)).slice(-2);
  }
  return ret + "}";
}

// Whenever scramble is called it will sleep for 500ms, to be able to
// use brute force, don't sleep at all. Instead just count how many
// times it's called. Usually sleep is called once after each digit
// has been verified to be correct. So by counting the number of
// calls to sleep we know how many bytes are correct.
function bypassSleep(Solver) {
    Solver.sleep.implementation = function(input) {
    sleepCount++;
    return input;
  };
}
