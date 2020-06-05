---
layout: post
title:  "Solving OWASP MSTG UnCrackable App for Android Level 3"
date:   2020-06-05
comment_issue_id: 5
---

With [level 1][level1] and [level 2][level2] of the OWASP MSTG UnCrackable App for Android under our belt it's time to take a stab at [level 3][owasp-l3]. They call it "The crackme from hell!" and it is indeed significantly more difficult than the previous two.

## Preparations
We'll be using [dex2jar][dex2jar], [JD-GUI][jd-gui] and, [Ghidra][ghidra] this time as well. Like the [last time][level2], we start by downloading the apk from the [crackmes page][owasp-l3] and installing it on the device. We also run it trough dex2jar (`d2j-dex2jar.bat -f UnCrackable-Level3.apk`), open the jar file in JD-GUI and extract the library with the native code so we can open it in Ghidra.

## Taking a first look

`onCreate` has a bit more code and does more checks this time, but it's similar. If tampering is detected `showDialog()` is called.

{% include image.html url="/learning-frida/assets/uncrackable3/onCreate.png" description="The onCreate() method"%}

Let's use the same root check bypass as we did before and run the app.

{% highlight javascript %}
Java.perform(function(){
  MainActivity.showDialog.implementation = function(s) {
    console.log("Tamper detection suppressed, message was: " + s);
  }
});
{% endhighlight %}

That didn't help much, the app crashes on startup:

```
PS D:\src\frida> frida -U -f owasp.mstg.uncrackable3 -l uncrackable3.js --no-pause
...
[Android Emulator 5554::owasp.mstg.uncrackable3]-> Process crashed: Trace/BPT trap
...
signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
...
backtrace:
    #00 pc 000000000007f757  /system/lib64/libc.so (offset 0x7f000) (tgkill+7)
    #01 pc 000000000000374a  /data/app/owasp.mstg.uncrackable3-N9smELPr4V3hD7iWPqaeug==/lib/x86_64/libfoo.so (goodbye()+10)
...
```

Taking a look at the output in logcat shows a similar record, but it also shows this additional message:
```
32298-32332/owasp.mstg.uncrackable3 V/UnCrackable3: Tampering detected! Terminating...
```

## Native side tampering detection

It seems like there is tampering detection done on the native side as well. The error messages shown provides us with several clues on what to look for. The crash happens directly on startup, so the tampering detection probably takes place when the library is initialized. It also mentions signal 6 and a function named `goodbye()`.

Let's go for the `goodbye()` function and find that in Ghidra. It looks like it just calls `raise(6)` and exits, which is the behavior we saw. So it might be more interesting to see where it's called from.

{% include image.html url="/learning-frida/assets/uncrackable3/frida_detection.png" description="The function that calls goodbye()"%}

I'm looking at the arm version of the native library since the decompiled code was slightly easier to understand with the arm version. All the different native libraries are copied from the same code, so as long as we are just trying to understand what the code does it doesn't matter which one we are looking at.

Toward the end of the function we can see the string `Tampering detected! Terminating...` that we saw in logcat. It seems like this code is called if `strstr` can find the substring "frida" or "xposed" in some other string. Since we are using Frida this triggers and the app is killed by calling `goodbye()`.


## Bypassing Frida detection with Frida

`strstr` is used to search for Frida, so let's hook this function and make it return false whenever there is a comparison done against "frida". [Last time][hooking-strncmp] we hooked into `strncmp` from the `libfoo.so` library. To be able to do that the library must first be loaded, however the Frida detection is run when the library is initialized so we can't use this approach.

Since `strstr` is a standard library function we can hook it in `libc` instead which is available even before `libfoo.so` have been loaded.

{% highlight javascript %}
  Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function(args) {
      this.fridaDetected = 0;
      if (args[0].readUtf8String().indexOf("frida") != -1) {
        this.fridaDetected = 1;
      }
      else {
        this.fridaDetected = 0;
      }

    },
    onLeave: function(retval) {
      if (this.fridaDetected == 1) {
        retval.replace(0);
      }
    }
  });
{% endhighlight %}

When `strstr` is called we check if the first argument contains the string "frida" then we remember that until the function returns. When it returns we replace the return value if Frida was detected to make the Frida check fail every time without changing its behavior in other cases.

## Looking for the secret

Now that we can start the app it's time to find the secret. The secret is located in the native library, but a quick look at the java code shows us two interesting things.

1. The native function `Java_sg_vantagepoint_uncrackable3_MainActivity_init` is called with a hard coded string referred to as `xorkey`.
2. The code check seems to be done by the native function `Java_sg_vantagepoint_uncrackable3_CodeCheck_bar`.

First we take a look at the init function. Here we can see that it basically just stores the provided `xorkey` so that it can be used later.

{% include image.html url="/learning-frida/assets/uncrackable3/native_init_function.png" description="The init function. I've modified a few names to more easily spot them in other parts of the code."%}

Let's take a look at the code check function next. This one is a bit more tricky, but if we work backwards from where it returns we can figure it out.

{% include image.html url="/learning-frida/assets/uncrackable3/code_check.png" description="The central part of the code check function, also here with a couple of modified names."%}

This function returns true (or 1) when the given input matches the secret string. This only happens if it manages to do `0x18` iterations of the while loop.

In each iteration of the while loop it does an xor with the `xorkey` provided in the init function and a comparison. If the comparison fails it bails out. This basically means that it checks that `stored_secret ^ xorkey == input`.

Now we need to figure out where the secret comes from. The variable for the secret is called `local_40` in the screenshot above and it seems to be the argument to the function that I renamed to `calculate_secret`. Taking a quick look at this function shows that it's about 1500 lines of decompiled code, so it won't be easy to reverse engineer that. 

Luckily we don't need to do that. `calculate_secret` takes a pointer as argument and does its magic to generate the secret. Once the function return the secret will be stored at the memory address indicted by the pointer. So if we could just take a look at the memory when the function returns we should be able to get the secret.


## Hooking the secret generator
If we could hook the function that generates the secret we should be able to get the secret when it returns. However this is not an exported function so we can't find it by `Module.findExportByName()` like we've done earlier. But that doesn't have to stop us, `Module.findExportByName()` returns a pointer to where the function is located in memory. We can also generate this pointer manually.

Now we need to make sure we open up the same native library in Ghidra as we are running on our device. For me this is the x86_64 library. Then we find our way to the function in question and take a look at it's memory address in the assembler view. For the x86_64 library this function is located at address `0x12c0` inside this library.

{% include image.html url="/learning-frida/assets/uncrackable3/function_address.png" description="The location of the function we want to hook."%}

With the internal offset known we can get the pointer to the function by calling `Module.findBaseAddress('libfoo.so').add(0x12c0)` and then we can hook that as usual.

As a quick check that our theory is correct let's hook the secret generator function and print the content of the memory before and after the function is called. Dumping the memory can be done with the [global Frida function][global-frida] `hexdump`. To do this let's add the following hook:

{% highlight javascript %}
Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0x12c0), {
  onEnter: function(args) {
    console.log("Secret generator on enter, address of secret: " + args[0]);
    this.answerLocation = args[0];
    console.log(hexdump(this.answerLocation, {
      offset: 0,
      length: 0x20,
      header: true,
      ansi: true
    }));
  },
  onLeave: function(retval) {
    console.log("Secret generator on leave");
    console.log(hexdump(this.answerLocation, {
      offset: 0,
      length: 0x20,
      header: true,
      ansi: true
    }));
  }
});
{% endhighlight %}

What we should see when running this is that the memory is cleared in `onEnter` and that it has some value in `onLeave`.

{% include image.html url="/learning-frida/assets/uncrackable3/secret_generation.png" description="Memory content before and after the call to the function that calculates the secret."%}

Great! It looks like we are on the right track, but to reveal the real secret we need to xor this with the xorkey.

## Getting the xorkey
The xorkey is hardcoded in the Java code, but I want to practice using Frida so I'm going to grab it during the initialization instead. As we saw earlier when looking at the native init function, the key was copied using `strncpy`. `strncpy`'s second argument is a pointer to the data that should be copied so let's hook `strncpy` and copy that data using Frida's `NativePointer.readByteArray()` and store the result in a global variable.

{% highlight javascript %}
  const secretLength = 24;
  var xorkey = undefined;
  Interceptor.attach(Module.findExportByName("libc.so", "strncpy"), {
    onEnter: function(args) {
      if (args[2].toInt32() == secretLength) {
        xorkey = new Uint8Array(args[1].readByteArray(secretLength));
      }
    },
  });
{% endhighlight %}
## Decoding the secret
To be able to decode the secret we need to xor the encoded version with the key byte for byte. Let's write a small function that does that. This is pure javascript without using any Frida apis:

{% highlight javascript %}
  function xorByteArrays(a1, a2) {
    var i;
    const ret = new Uint8Array(new ArrayBuffer(a2.byteLength));
    for (i = 0; i < a2.byteLength; i++) {
      ret[i] = a1[i] ^ a2[i];
    }
    return ret;
  }
{% endhighlight %}

Now we have everything we need to actually get the secret, so let's update the hook for the secret generator function we created earlier and put it in a separate function to keep the code clean.

{% highlight javascript %}
  function attachToSecretGenerator() {
    // function that generates the secret code is located at 0x12c0
    Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0x12c0), {
      onEnter: function(args) {
        // First (only) argument is the address of where the secret should be stored
        this.answerLocation = args[0];
      },
      onLeave: function(retval) {
        var encodedAnswer = new Uint8Array(this.answerLocation.readByteArray(secretLength));
        var decodedAnswer = xorByteArrays(encodedAnswer, xorkey);
        console.log("Secret key: " + String.fromCharCode.apply(null, decodedAnswer));
      }
    });
  }
{% endhighlight %}

This is pretty straight forward, in `onEnter` we store the location in memory where the secret will be located. in `onLeave` we copy the secret from memory and then xor it with the xorkey we extracted earlier. With all this we should be able to get the secret in a readable format.

## Putting it all together
We have everything we need, all that remains is to put everything together. Let's call our `attachToSecretGenerator()` function when the `MainActivity` constructor is called to avoid attaching to it multiple times.

{% highlight javascript %}
  var MainActivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
  MainActivity.$init.implementation = function() {
      this.$init();
      attachToSecretGenerator();
  };
{% endhighlight %}

Let's also call the `check_code()` method with a dummy string as parameter to trigger the code check from `onResume()`. When this string is compared against the real secret our hooks will be run and real secret will be printed to the console.

{% highlight javascript %}
  MainActivity.onResume.implementation = function() {
      this.onResume();
      // Find the CodeCheck instance that was created by the app in onCreate()
      // Then call it with a dummy string.
      Java.choose("sg.vantagepoint.uncrackable3.CodeCheck", {
        onMatch : function(instance) {
          instance.check_code(Java.use("java.lang.String").$new("dummy"));
          return "stop";
        },
        onComplete:function() {}
      });
  };
{% endhighlight %}

All we have to do now is to run the script and the secret will be revealed. 

{% include image.html url="/learning-frida/assets/uncrackable3/secret_found.png" description="We have now extracted the secret and completed the final level of the UnCrackable app for Android."%}

## Things learned
In addition to getting more experience with analyzing native code we got to use some new parts of Frida as well.
* We had to hook standard library functions directly in the standard library rather than in the library we are analyzing to have them hooked as before the library is initialized.
* We learned how to hook unexported functions by using `Module.findBaseAddress('libfoo.so').add(<location of the function in the library>)`.
* Using `hexdump` is useful when you want to look directly at the memory.
* With `NativePointer.readByteArray()` we can read data from memory.
* `Class.$init.implementation` can be used to to replace the constructor implementation of Java classes.

## Useful links

There were some anti-debugging logic in the native code that we didn't have to bypass, but that you might have seen while analyzing the code. The creator of the UnCrackable apps has written an [article about anti-debugging][anti-debugging] techniques that describes this logic.

In [another article][frida-detection] the same person also writes about how you can detect Frida and the detection that we bypassed in this challenge is described in the article.

With all the UnCrackable apps solved one final thing that could be of interest is to take a look at the [actual source code][uncrackable-code] for the apps that we have cracked.

And of course the complete version of the Frida script I wrote for this challenge is [available on GitHub][my-code].


[level1]: {{ site.baseurl }}{% post_url 2020-05-16-uncrackable1 %}  
[level2]: {{ site.baseurl }}{% post_url 2020-05-23-uncrackable2 %}
[owasp-l3]: https://github.com/OWASP/owasp-mstg/tree/master/Crackmes#uncrackable-app-for-android-level-3
[ghidra]: https://github.com/NationalSecurityAgency/ghidra
[dex2jar]: https://github.com/pxb1988/dex2jar
[jd-gui]: https://java-decompiler.github.io
[global-frida]: https://frida.re/docs/javascript-api/#global
[hooking-strncmp]: {{ site.baseurl }}{% post_url 2020-05-23-uncrackable2 %}#comparing-strings
[anti-debugging]: http://www.vantagepoint.sg/blog/89-more-android-anti-debugging-fun
[frida-detection]: http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida
[uncrackable-code]: https://github.com/commjoen/uncrackable_app
[my-code]: https://github.com/nibarius/learning-frida/blob/master/src/uncrackable3/uncrackable3.js