---
layout: post
title:  "Hacker101 CTF - Oauthbreaker"
date:   2020-07-12
comment_issue_id: 7
---

[Hacker101](https://www.hacker101.com) is a free class for web security with many different CTF challenges. A couple of these are Android challenges and I'm going to tackle the Oauthbreaker challenge here. This challenge have two flags. There is no need to use Frida to find the first flag, but for the second flag Frida comes in handy, so that's what I'll be focusing on.

## Taking a look at the code

We start by installing the apk and starting it on our device, run the apk trough [dex2jar](https://github.com/pxb1988/dex2jar) and opening the resulting jar file in [JD-GUI](https://java-decompiler.github.io) to see the source code.

The `MainActivity` and the `Browser` have some oauth related code, but the really interesting part is in the `WebAppInterace` class. There is a method here with the interesting name `getFlagPath`.

{% include image.html url="/learning-frida/assets/h101-oauthbreaker/webappinterface.png" description="This method might just give us the flag location" %}

The method does a bunch of convoluted operations to generate a string, but instead of trying to understand the code, let's just call the method and see what it returns. To do this we need to first create an instance of the `WebAppInterace` class. The constructor takes a `Context` as parameter, but since this is not used we can just pass in `null`.

{% highlight javascript %}
Java.perform(function(){
  var WebAppInterface = Java.use("com.hacker101.oauth.WebAppInterface");
  var flag = WebAppInterface.$new(null).getFlagPath();
  console.log("Flag path: " + flag);
});
{% endhighlight %}

## Capturing the flag

With the Oauthbreaker app running on the device we load our script and see what we get: `frida -U -l oauth.js com.hacker101.oauth`.

{% include image.html url="/learning-frida/assets/h101-oauthbreaker/frida.png" description="Revealing the flag path" %}

Now we have a path to an html file that we need to use somewhere. Clicking on the "Authenticate" button in the app opens the associated oauth page. Just replace `oauth?` and everything after that in the url with the flag path and the actual flag will be revealed. Submit the flag on the Hacker101 page to be awarded with 4 points.

[Full code is available on GitHub](https://github.com/nibarius/learning-frida/blob/master/src/h101/oauth.js)


