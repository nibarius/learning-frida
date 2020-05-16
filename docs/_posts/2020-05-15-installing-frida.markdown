---
layout: post
title:  "Installing Frida"
date:   2020-05-15
---

The first thing we need to do is to install the Frida CLI tools, which is is fairly [straight forward](https://frida.re/docs/installation/). Basically you need to have python installed, then you just run `pip install frida-tools` and you're done.

## Prepare an Android device

We also need an Android device that will be used together with Friday. It's possible to use Frida on non-rooted phones, but it's not quite as straight forward. So for an easy start I'm using an emulator running an Android 9 (Pie) system image without any Google services. Without Google services you can get root access right away which makes things easier.

I did try an older Android version at first, but then Frida crashed on startup so I decided to go with Android 9 that works fine for me.

When installing the Android system image for the emulator, pay attention to which version you are using, I'll picked an `x86_64` version since that matches my computer's architecture.

{% include image.html url="/learning-frida/assets/install/install_emulator.png" description="Emulator setup" %}

## Install the Frida server on the phone

The Frida web site has a [good guide](https://frida.re/docs/android/) explaining how to get Frida set up on an Android device.

When you download the Frida server for Android make sure you pick one that matches the architecture of your device / emulator image. Since I'm using `x86_64` I downloaded the Frida server `frida-server-12.8.20-android-x86_64.xz`

Extract the server and possibly rename it to something shorter like `frida-server` to make things easier.

Now it's time to install the Frida server on the phone, first switch to root by running `adb root` in a terminal and then push the Frida server to the phone: `adb push frida-server /data/local/tmp/`.  After this we just have to connect to the phone and start the server.

```
adb shell
cd /data/local/tmp
chmod 755 ./frida-server
./frida-server
```

Tip: you can see if you have root access on the phone by looking for `#` on the input line in the shell, if `$` is shown instead of `#` you don't have root access.

{% include image.html url="/learning-frida/assets/install/adb_shell_root.png" description="Non-root vs root" %}

## Test that Frida is working

Open a new console on your computer and run `frida-ps -U -a` to list all applications (`-a`) running on the phone / attached usb device (`-U`)

{% include image.html url="/learning-frida/assets/install/listing_running_apps.png" description="Listing running apps with Frida" %}

Now that everything is up and running we can [get started using Frida]({{ site.baseurl }}{% post_url 2020-05-16-unckrackable1 %}).
