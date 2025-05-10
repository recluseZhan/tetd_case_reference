Signed application for TETD, using SHA-256 and RSA-3072. Run as follows.

```
cd application_level && sh test.sh
[or cd school_level && sh test.sh]
```

The hash algorithm used is SHA-256, accelerated by SHA-NI. The RSA in the school\_level directory uses Montgomery multiplication and Chinese Remainder Theorem (CRT) acceleration. In actual applications, it is recommended to refer to the application\_level subdirectory. 
