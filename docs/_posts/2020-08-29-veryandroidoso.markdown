---
layout: post
title:  "DEFCON Quals 2019 Veryandroidoso"
date:   2020-08-29
comment_issue_id: 9
---

This time it's time to tackle the [DEFCON Quals 2019 Veryandroidoso][challenge] challenge. It's a reverse engineering challenge with one flag that you're supposed to find. It's a bit different from the challenges I've done earlier with more focus on reversing the algorithm rather than just finding the right place to pick up the secret from.

## Analyzing the application

[Jadx][jadx] wasn't able to handle this apk very well. It produced difficult to read java code that was even incorrect in some places, so I ended up using [JD-GUI][jd-gui] instead.

{% include image.html url="/learning-frida/assets/veryandroidoso/jdgui-vs-jadx.png" description="JD-GUI produced much better code than jadx, especially around the return statements seen here" %}

The application is fairly simple, when you submit a flag it check that it begins with `OOO{`, ends with `}` and contains 18 hexadecimal characters in between. The hexadecimal characters are converted to nine integers between 0 and 255 and passed to the `solve()` method where all the work is done.

The solve method is around 6000 lines of if statements that maps each argument to another number before it checks if they are correct. It also have methods like `scramble` and `getSecretNumber` that converts the input further. There is also a similar conversion made in native code before the final check is done whether or not the given argument is acceptable.

This makes it really hard to figure out what the correct input is by just analyzing the code. There is also no check against a hard coded secret that we can hook. So we'll have to find the flag by brute force. However there are some brute force protection in place that we need to bypass first.

## Bypassing the brute force protection
The `scramble` method is called several times every time the `solve` method is called, and it also calls the `sleep` method which sleeps for 500 milliseconds. So any attempt at brute focing `solve` will end up with sleeping most of the time. We can get around this by replacing the implementation of the `sleep` method with one that just returns the sleep duration directly without actually sleeping.

We'll also count the number of times the sleep method is called, since this will come in handy later on.

{% highlight javascript %}
var sleepCount = 0;
function bypassSleep(Solver) {
    Solver.sleep.implementation = function(input) {
    sleepCount++;
    return input;
  };
}
{% endhighlight %}

## Finding the correct values for arguments 1-4

The beginning of the `solve` method looks as follows:

{% highlight java %}
    int j = scramble(13);
    if (paramInt1 == 0) {
      i = m0(100, getSecretNumber(j));
    } else if (paramInt1 == 1) {
      i = m0(190, getSecretNumber(j));
    ...
    } else if (paramInt1 == 255) {
      i = m0(61, getSecretNumber(j));
    } else {
      i = 0;
    } 
    if ((i & 0xFF) != 172)
      return false; 
    j = scramble(j);
    if (paramInt2 == 0) {
{% endhighlight %}

It first calculates a new value based on the first argument, then it checks if that calculated value is 172. If it's not it returns false immediately. If the first argument is correct it continues with verifying the second argument by first calling `scramble` before it calculates a new value to compair against.

As we remember from earlier, `scramble` calls `sleep` and we are counting how many times sleep is called. This means that if we call `solve` and `sleep` is called only once it means the first argument is wrong. If `sleep` is called twice or more it means the first argument is correct.

{% highlight javascript %}
var a = 0;
do {
  sleepCount = 0;
  Solver.solve(a, 0, 0, 0, 0, 0, 0, 0, 0);
  if (sleepCount > 1) {
    console.log("accepted value for a found: " + a);
    tmp = a;
  }
} while (sleepCount == 1 && a++ < 256)
{% endhighlight %}

With this we can find out what the expected value of the first parameter should be in at most 256 attempts. The second parameter works exactly the same so we can take the same approach there.

The check for the third and fourth parameter accepts more than one value. So we have to modify our approach a bit and record all accepted values rather than only the first.

## Finding the correct values for arguments 5-6

When we get to the fifth argument it's a bit different. Argument 5 is checked exactly as the ones before, but argument 6 is special. There is no call to `scramble` or any special conversions done, instead it's just a simple bitmask check. So the correct code for both argument 5 and 6 have to be correct for `scramble` to be called the next time.

{% include image.html url="/learning-frida/assets/veryandroidoso/arg56.png" description="Code for argument 5 and 6" %}

Since the sixth argument is checked against a bitmask it's easy to find all acceptable values.

{% highlight javascript %}
var acceptable = [];
for(var i = 0; i < 256; i++) {
  if ((i & 0x41) == 65) {
    acceptable.push(i);
  }
}
{% endhighlight %}

Once we have the sixth argument we can find the fifth using the same method as earlier and just pass in an acceptable value for argument six. Argument seven and eight works just like the first so those are straightforward to find.

## Finding the last argument

Things gets a bit more complicated on the last argument. First the native function `m9` is called with one argument based on all previous arguments. Later the native function `m8` is called to generate the number that the final check is made against. The output of `m8` depends on what `m9` was called with earlier, which means all arguments must be correct before we can find the correct value of the last argument.

We will just have to try all combinations of the previously found valid candidates together with all possible values of the last argument (0-255) until the solve method returns true.

{% highlight javascript %}
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
                    ...
{% endhighlight %}

To check all options about a million calls to `solve` is needed, but luckily the right answer is found after around shortly after 30,000 calls so it doesn't take too long to find the code. For me the last step takes around 7 minutes.

## Constructing the flag

With the correct values for all parameters known all that remains is to construct the real flag which is done by converting the 9 arguments to a hex string and adding `OOO{` and `}` to it.

{% highlight javascript %}
function getFlag(bytes) {
  var ret = "OOO{";
  for(var i = 0; i < bytes.length; i++) {
    ret += ("0" + bytes[i].toString(16)).slice(-2);
  }
  return ret + "}";
}
{% endhighlight %}

{% include image.html url="/learning-frida/assets/veryandroidoso/solved.png" description="Veryandroidoso solved" %}

[Full code is available on GitHub][my-code]

[challenge]: https://archive.ooo/c/VeryAndroidoso/272/
[jadx]: https://github.com/skylot/jadx
[jd-gui]: https://java-decompiler.github.io
[my-code]:https://github.com/nibarius/learning-frida/blob/master/src/veryandroidoso/veryandroidoso.js
