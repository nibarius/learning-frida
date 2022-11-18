---
layout: post
title:  "Bypassing certificate pinning with Frida"
date:   2022-11-18
comment_issue_id: 32
---

Being able to [intercept https traffic][https] can often be useful when analyzing applications. Some apps are however using certificate pinning as a defense-in-depth strategy which makes this more difficult. In this article I'm going to show how you can bypass the certificate pinning using [Frida][frida]. To follow along you need to have Frida installed, if you don't have it installed, please start by reading [Installing Frida][installing].

The screenshots in this article shows how I'm bypassing certificate pinning in Whatsapp, but the process I describe is general and should work on most other apps as well.

## What is certificate pinning?

When an app connects to a remote server over https an encrypted connection is established between the app and the server as long as the server's certificate is signed by a trusted authority. Most apps are using the underlying operating system's list of trusted certificates. This means that if you can install your certificate on the operating system you can do a [man in the middle attack][mitm] and intercept the traffic and present your certificate when the app is connecting to the remote server.

To mitigate the risk for these kinds of attacks some apps use certificate pinning. This means that they have a list of trusted certificates and that they will only establish a connection if the remote server has a certificate that is on that list. Even if the server's certificate is trusted by the system it will be rejected if it's not on the app's allow list. This ensures that the app is communicating with a trusted server.

{% include image.html url="/learning-frida/assets/bypassing-pinning/connection-rejected.png" description="Trying to do a MITM attack on Whatsapp just results in a connection error since Burp's certificate is not trusted by Whatsapp" %}

# How does bypassing work?

To be able to bypass certificate pinning we need to get the app to accept our certificate. There are many different possibilities here. You could for example decompile the app, strip out the certificate pinning code and recompile it. Finding the list of trusted certificates and updating it to include your certificate could also be an option in some cases.

These methods are complicated and time consuming, so a better approach is often to bypass the pinning dynamically with Frida while the app is running. The basic concept is to find the method that checks the server's certificate against the list of trusted certificates and modify it so that it say that any certificate is trusted.

# Bypassing certificate pinning

It's fairly complicated to implement certificate pinning completely on your own and many frameworks have support for certificate pinning. This means that most apps use one of a fairly limited set of libraries to do certificate pinning. Bypassing certificate pinning is also something that many people want to do, so there are many different solutions available for bypassing certificate pinning.

This means that we don't really have to write any code at all, we just need to find a suitable Frida script and run it. The [frida-multiple-unpinning script][fmu] is one script I've had success with in the past so that's what I'm going to use.

Download the script, start Frida with this script and launch the app you want to bypass certificate pinning on.

{% include image.html url="/learning-frida/assets/bypassing-pinning/bypassing-pinning.png" description="Start Frida, load the script and spawn the app to bypass certificate pinning" %}

With this, the app's certificate pinning should be bypassed and you can intercept the network traffic.

{% include image.html url="/learning-frida/assets/bypassing-pinning/traffic-intercepted.png" description="Pinning bypass succeeded, now we can see the traffic. However as Whatsapp is using end to end encryption in addition to TLS much of the payload is encrypted and not readable." %}

If this doesn't work on the app you are working with it might be using some other certificate pinning method that the frida-multiple-unpinning script does not support. In that case you could try some other unpinning scripts or try to find some other ways of bypassing certificate pinning that might work for your app.

## Lessons learned

Bypassing certificate pinning using Frida can often be quite easy if you're familiar with using Frida. Since it's a common use case there are many scripts and tools available for bypassing certificate pinning and we don't even have to write any code. Don't let certificate pinning stop you in the future.



[https]: {{ site.baseurl }}{% post_url 2021-01-23-sniffing-https-traffic %} 
[installing]: {{ site.baseurl }}{% post_url 2020-05-15-installing-frida %}
[frida]: https://frida.re
[mitm]: {{ site.baseurl }}{% post_url  2021-01-23-sniffing-https-traffic %}#basics
[fmu]: https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/
