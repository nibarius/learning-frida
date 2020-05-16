---
layout: post
title:  "Solving OWASP MSTG UnCrackable App for Android Level 1"
date:   2020-05-16
comment_issue_id: 2
---

Now that we have [Frida set up]({{ site.baseurl }}{% post_url 2020-05-15-installing-frida %}), we can try to use it to solve the OWASP mobile security testing guide's [UnCrackable App for Android Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes#uncrackable-mobile-apps).

This challenge have a secret hidden inside an apk somewhere and the task is to find it.

## Preparations

In addition to Frida we are going to use two additional tools:
* [dex2jar](https://github.com/pxb1988/dex2jar) to convert the apk file to a jar file
* [JD-GUI](https://java-decompiler.github.io) to decompile the jar file to be able to see the source code of the of the original apk.

Both dex2jar and JD-GUI are trivial to set up, just download the tools and extract them to the desired location.

Download `UnCrackable-Level1.apk` and install it on your device by running `adb install UnCrackable-Level1.apk`. Also run it trough dex2jar (`d2j-dex2jar.bat -f UnCrackable-Level1.apk`) and open the jar file in JD-GUI.

## Getting started

Now we're all set to start experimenting with the app. Start by just running it on your device.

```
  +---------------------------------+
  |  Root detected!                 |
  |                                 |
  |  This is unacceptable. The app  |
  |  is now going to exit.          |
  |                                 |
  |   OK                            |
  +---------------------------------+
```

That's not good, looks like the app doesn't allow being run on a rooted device. Let's switch to JD-GUI and take a look at the code. Since this happens on startup the `MainActivity` class and the `onCreate` method is probably a good place to start.

It looks like the apps does several different root checks and one check if the app is debuggable. If this is the case the method `a` is called which shows the dialog we saw and then exits as soon as the dialog is closed.

{% include image.html url="/learning-frida/assets/uncrackable1/root_detection.png" description="Root detection code" %}

Let's try to use Frida to replace the method `a` with another method that doesn't do anything.

## Bypassing root detection
By running `frida -U owasp.mstg.uncrackable1` it's possible to attach to the application. But this requires that the application is already running. However the application does the root check on startup, and by the time we have attached it's already too late.

So we need to make sure we modify the app before we start it. We'll start by writing the code needed to replace the original implementation of the `a` method. Create file called `unckrackable1.js` with the following content:

{% highlight javascript %}
Java.perform(function() {
  Java.use("sg.vantagepoint.uncrackable1.MainActivity").a.implementation = function(s) {
    console.log("Tamper detection supressed, message was: " + s);
  }
});
{% endhighlight %}

The [Frida javascript api documentation](https://frida.re/docs/javascript-api/#java) describes these functions and can be helpful for understanding what we're actually doing. But basically the enclosing `Java.perform()` takes care of running the code we write.

`Java.use` gets a JavaScript wrapper for the given class name so that we can interact with it. As mentioned earlier we want to start by modifying the `a` method in the `MainActivity` to bypass the root detection.

By using `implementation` we can replace the implementation of the method. Let's just write a message to the console so we see that the method was called.

With this in place we can run Frida again, this time doing it without first starting the app and using the command `frida -U --no-pause -l uncrackable1.js -f owasp.mstg.uncrackable1`. `-f` will start the given package and pause the main thread before the app have a chance to run. the `-l` flag provides a javascript that should be loaded. This script holds all the modifications that we will be doing to the app. Since we include a script to be loaded there is no need to pause the main thread on startup, so we pass along the `--no-pause` to prevent this.

{% include image.html url="/learning-frida/assets/uncrackable1/root_bypassed.png" description="Root detection bypassed" %}

## Finding the secret

The app now starts and instead of the root detection dialog we just get a printout in the console. That's a good start, now we can actually use the app. Looks like there's a text field where you can enter a secret and verify it. We're not going to be able to guess the secret, so let's go back to JD-GUI and take a look at the code again.

{% include image.html url="/learning-frida/assets/uncrackable1/verify.png" %}

In the `MainActivity` there is a `verify()` method that calls `sg.vantagepoint.uncrackable1.a.a()` with the entered string, it seems like this method returns true if the secret is correct. Let's take a look at this method.

{% include image.html url="/learning-frida/assets/uncrackable1/string_checker.png" %}

Ok, that method seems to contain the secret encrypted with AES and base64 encoded. An obfuscated version of the encryption key seems to be there as well. The method `b` in the same class seems to handle the de-obfuscation.

## Getting the secret

But let's ignore that, looking closer at the code it looks like `sg.vantagepoint.a.a.a` is responsible for the decryption of the secret. So if we can just see what this method returns we should be able to get our hands on the secret.

Time to update `unckrackable1.js` with some additional code:
{% highlight javascript %}
  function bufferToString(buf) {
    var buffer = Java.array('byte', buf);
    var result = "";
    for(var i = 0; i < buffer.length; ++i){
      result += (String.fromCharCode(buffer[i] & 0xff));
    }
    return result;
  }
  
  Java.use("sg.vantagepoint.a.a").a.implementation = function(ba1, ba2) {
    const retval = this.a(ba1, ba2);
    console.log("secret code is: " + bufferToString(retval));
    return retval;
  }
{% endhighlight %}

`sg.vantagepoint.a.a.a` returns an array of bytes, which isn't very readable. So we start by creating a helper method called `bufferToString` that converts an array of bytes to a string as described [in this answer on the Reverse Engineering StackExchange](https://reverseengineering.stackexchange.com/a/22255).

With that in place we continue to modify the implementation `sg.vantagepoint.a.a.a` in a similar way to before. This time we first call the original implementation, convert the return value (the secret code) to a string and print it to the console before returning it.

All we have to do now is to save the file and tap the verify button in the app. Frida automatically reloads the script when saved, so you don't even have to restart Frida or the app. When pressing verify the secret is revieled in the console. Go ahead and try it in the app to make sure you got it right.

{% include image.html url="/learning-frida/assets/uncrackable1/code_found.png" description="We got the secret code!"%}

## Improving the process

We could be done here, but why not take the chance to learn a bit more? Wouldn't it be nice if we could get the secret right away without having to first guess something. Let's try to modify the `onResume()` method so that it tells us the secret when called. If you're familiar with the [Activity lifecycle in Android](https://developer.android.com/guide/components/activities/activity-lifecycle) you might know that this is a method that's called when the app becomes visible. So that feels like convenient place to put code we want run when the app is started.

Then we need to figure out what code we want to run. Earlier we saw that the `verify()` method calls `sg.vantagepoint.uncrackable1.a.a()` with the manually entered value. We could just call this ourselves with a dummy value to trigger our code that prints the secret when it's accessed. Since this method is a static method we can just call it right away without having to create a new instance. This makes the code we need to add fairly straight forward:

{% highlight javascript %}
  Java.use("sg.vantagepoint.uncrackable1.MainActivity").onResume.implementation = function() {
    this.onResume();
    Java.use("sg.vantagepoint.uncrackable1.a").a("dummy");
  }
{% endhighlight %}


Just update the code and save the file. To see that it works turn off the screen on the phone and turn it on again since this will trigger `onResume()` to be called.

## Things learned
We've only done fairly simple things so far, but with absolutely no prior experience with Frida we've actually learned a lot. Here are some highlights:

* How to start Frida (`frida -U`) with a JavaScript loaded (`-l`) and spawn an app (`-f <package name>`) to be able to modify app behavior during early startup.
* What a basic JavaScript that Frida loads should look like
* How to replace the implementation of a method using `Java.use("<class>").<method>.implementation`
* How to call the original implementation of the method being replaced
* How to convert an array of bytes to a string
* How to call static methods

[Full code is available on GitHub](https://github.com/nibarius/learning-frida/blob/master/src/unckrackable1/uncrackable1.js)

