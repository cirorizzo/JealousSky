# JealousSky

##Encryption/Decryption Library for Android
--------

JealousSky is an efficient library to encrypt and decrypt data for Android.

With JealousSky is possible to decrypt simple String or even image files as return a Bitmap.

The project is still in progress and any contribuition is accepted.

At the moment Jealous Sky support AES 128bit encryption.


![](static/ic_jealoussky_logo.png)


Download
--------
You can download a jar from GitHub's [releases page][1].

Or use Gradle:

```gradle
repositories {
    jcenter()
    mavenCentral()
}

dependencies {
    compile 'com.github.cirorizzo.jealoussky:0.2'
}
```

Or Maven:

```xml
<dependency>
    <groupId>com.github.cirorizzo</groupId>
    <artifactId>jealoussky</artifactId>
    <version>0.2</version>
</dependency>
```

How do I use JealousSky?
-------------------
Checkout the [GitHub wiki][2] for pages on a variety of topics.

Simple use cases will look something like this:

```java
// For a image file decryption:

    JealousSky jealousSky = JealousSky.getInstance();
    
    jealousSky.initialize(
                    "longestPasswordEverCreatedInAllTheUniverseOrMore",
                    "FFD7BADF2FBB1999");
                    
    InputStream isEncrypted = new FileInputStream(new File(epic_fail_image.png.enc))
    
    ImageView imageViewDecrypted = (ImageView) findViewById(R.id.imageView);
    
    // Decrypting the InputStream
    imageViewDecrypted.setImageBitmap(jealousSky.decryptToBitmap(isEncrypted)));
    
    // Or Decrypting from the Assests
    imageViewDecrypted.setImageBitmap(jealousSky.decryptToBitmap(getAssets().open("spider-symbol.png.enc")));
```

Android SDK Version
-------------------
JealousSky requires a minimum SDK version of 16.

License
-------
GNU General Public License 3.0. See the [LICENSE][3] file for details.

Status
------
[*Version 0.2*] is a stable public pre-release library.
Comments/bugs/questions/pull requests welcome!

Getting Help
------------
To report a specific problem or feature request, [open a new issue on Github][4]. For questions, suggestions, or
anything else, join or email [JealousSky's discussion group][6]

Author
------
Ciro Rizzo - @JackRix



[1]: https://github.com/cirorizzo/jealoussky/releases
[2]: https://github.com/cirorizzo/JealousSky/wiki
[3]: http://www.gnu.org/licenses/gpl-3.0-standalone.html
[4]: https://github.com/cirorizzo/jealoussky/issues/new?body=**JealousSky%20Version/Integration%20library%20%28if%20any%29**%3A%0A**Device/Android%20Version**%3A%0A**Issue%20details/Repro%20steps/Use%20case%20background**%3A%0A%0A**JealousSky%20initialize%20lines**%3A%0A%60%60%60java%0AJealousSky%20jealousSky%20=%20JealousSky.getInstance%28%29%3B%0AjealousSky.initialize%28...%29%3B%0AjealousSky.encrypt%28...%29%3B%0AjealousSky.decrypt%28...%29%3B%0A%60%60%60%0A%0A**Layout%20XML**%3A%0A%60%60%60xml%0A%3C...Layout%3E%0A%20%20%20%20%3CImageView%20android%3AscaleType%3D%22...%22%20...%20/%3E%0A%3C/..Layout%3E%0A%60%60%60%0A%0A**Stack%20trace%20/%20LogCat**%3A%0A%60%60%60ruby%0Apaste%20stack%20trace%20here%0A%60%60%60
[5]: https://developers.google.com/open-source/cla/individual
[6]: https://groups.google.com/d/forum/jealoussky-library
