---
layout: page
title: Links
permalink: /links/
---

# Android CTFs

* [CyberTruckChallenge19][cybertruck] - A CTF with three different challenges. The two first are pretty easy with Java code only and the third gets more difficult as it introduces native code. The third part is a great complement to the UnCrackable App's native challenges.
* [DEFCON Quals 2019 VeryAndroidoso][veryandroidoso] - A CTF that focus more on reversing an algorithm rather than finding a hard coded secret. It has some native code, but can be solved without working with the native code. I found this CTF fairly challenging.
* [EVABS][evabs] - Beginner friendly CTF with several different challenges of different types. A few of them can be solved with Frida. Great to start with.
* [FridaLab][fridalab] - A small beginner friendly app with 8 Frida challenges. Great for those who are just starting out with Frida and need to get some practice.
* [Hacker101][h101] - Several different CTFs of various kinds with a couple of fairly easy Android CTFs. Some of the challenges, like the Oauthbreaker challenge can be solved with Frida. A free HackerOne account is needed to do these.
* [hpAndro Vulnerable Application][hpandro] - An Android CTF written in Kotlin which is still under development. It currently has 101 different flags in a wide range of challenges, some of which are suitable for solving with Frida.
* [UnCrackable App][uncrackable] - A couple of different CTF apps, the first has only Java code and is also fairly beginner friendly. The second introduces native code and the third hides the secret better and adds native anti tampering code that needs to be bypassed. It's quite difficult, but entirely possible without prior experience in reversing native code.

[cybertruck]: https://github.com/nowsecure/cybertruckchallenge19
[evabs]: https://github.com/abhi-r3v0/EVABS
[fridalab]: https://rossmarks.uk/blog/fridalab/
[h101]: https://www.hacker101.com
[hpandro]: http://ctf.hpandro.raviramesh.info
[uncrackable]: https://github.com/OWASP/owasp-mstg/tree/master/Crackmes
[veryandroidoso]: https://archive.ooo/c/VeryAndroidoso/272/


# Tools
* [dex2jar][dex2jar] - command line tool for converting apks to jar files (among other things).
* [Burp Suite][burp] - Popular tool among pen-testers, contains among others an http(s) proxy.
* [Bytecode Viewer][bytecode-viewer] - Java/Android decompiler. Haven't used it much, but it looks like a promising alternative to Jadx.
* [Fiddler][fiddler] - A great, powerful and free http(s) proxy for Windows, my proxy of choice for analyzing, intercepting and modifying http(s) traffic.
* [Frida][frida] - dynamic instrumentation toolkit, and also the main purpose of this blog.
* [Ghidra][ghidra] - a free and open source reverse engineering tool, good as a free alternative to IDA.
* [Jadx][jadx] - Java decompiler. Quick and easy to use as you can open apk files directly and see the source code.
* [JD-GUI][jd-gui] - Java decompiler. Can't open apk files directly, so tools like dex2jar has to be used on the apk first. But once that's done it sometimes produces better results than Jadx.

[frida]: https://frida.re
[dex2jar]: https://github.com/pxb1988/dex2jar
[bytecode-viewer]: https://github.com/Konloch/bytecode-viewer
[jd-gui]: https://java-decompiler.github.io
[jadx]: https://github.com/skylot/jadx
[ghidra]: https://github.com/NationalSecurityAgency/ghidra
[burp]: https://portswigger.net/burp/communitydownload
[fiddler]: https://www.telerik.com/download/fiddler
