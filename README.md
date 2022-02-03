# AES/GCM min sample

This is an attempt of produce a sane and well-explained tiny code to show how to use (minimally)
AES-256/GCM into with Linux kernel crypto api. Instead of wasting hours grasping into code that
does not matter directly for your task.

I have waste some time on it and I hope you waste less of your time from now on.

>>"A good idea is an orphan without effective communication" -- Andrew Hunt, The Pragmatic Programmer.

You have found issues? Please, let me [know](https://github.com/rafael-santiago/linux-crypto-api-aes-gcm-min-sample) and
thank you!

## How can I clone it?

```
_ git clone https://github.com/rafael-santiago/linux-crypto-api-aes-gcm-min-sample
```

All code is within ``src`` subdirectory.

## How can I build?

```
cd src
make
```

If the build was successful you will got ``aes-gcm-min-sample.ko`` module.

## How can I test it?

It is just about inserting the produced ``LKM``. Supposing your cwd is the ``src`` subdirectory:

```
_ insmod ./aes-gcm-min-sample.ko
```

Watch the results by executing ``dmesg``.

If the encryption and decryption was done, the kernel module has inserted, so you need to remove it:

```
_ rmmod aes-gcm-min-sample
```

So folks, that's all!
I hope it be useful and saves your time ;)

