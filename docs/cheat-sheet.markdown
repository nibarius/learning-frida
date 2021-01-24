---
layout: page
title: Cheat sheet
permalink: /cheat-sheet/
---

# Android emulator setup

 * From [Installing Frida][installing-frida], installing Frida on a device with root access:
```
adb root
adb push frida-server //data/local/tmp/
adb shell
cd /data/local/tmp
chmod 755 ./frida-server
./frida-server
```

* From [Sniffing https traffic on Android 11]({{ site.baseurl }}{% post_url 2021-01-23-sniffing-https-traffic %}), installing a certificate from Burp Suite on an Android 11 emulator:
```
openssl x509 -inform der -in burp.cer -out certificate.pem
cp certificate.pem `openssl x509 -inform pem -subject_hash_old -in certificate.pem | head -1`.0
./emulator -avd rRoot -writable-system
adb push 9a5ba575.0 //sdcard/Download
adb root
adb shell avbctl disable-verification
adb reboot
adb root
adb remount
adb shell
cp /sdcard/Download/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0
reboot
```

Note: `//sdcard` and similar in adb push commands is to [make it work](https://stackoverflow.com/a/17139366/1730966) with git bash on Windows.

# Frida command line

* From [Installing Frida][installing-frida], list all running applications:
```
frida-ps -U -a
```
* From [Solving OWASP MSTG UnCrackable App for Android Level 1][uncrackable1]:
```
# Attach to a running application
frida -U owasp.mstg.uncrackable1
# Load a script and start a package
frida -U --no-pause -l uncrackable1.js -f owasp.mstg.uncrackable1
```

* To upgrade Frida Follow the instructions on <https://frida.re/docs/android/> to install the latest version of frida-server on the phone. Then to upgrade Frida on the computer run:
```
pip install --upgrade frida-tools
```


# Other tools
* From [Solving OWASP MSTG UnCrackable App for Android Level 1][uncrackable1], using dex2jar:
```
d2j-dex2jar.bat -f UnCrackable-Level1.apk
```

[installing-frida]: {{ site.baseurl }}{% post_url 2020-05-15-installing-frida %}
[uncrackable1]: {{ site.baseurl }}{% post_url 2020-05-16-uncrackable1 %}