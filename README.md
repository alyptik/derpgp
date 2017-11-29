# derpgp - A simple GnuPG to PKCS#1/PKCS#8 conversion tool.

*WIP*

## Dependencies

* libgcrypt
* libgpg-error

> **Optional:**
> * Python2 (Bignum Unit Tests)

## Usage
```bash
./derpgp [-hv] [-i<in.gpg>] [-o<out.pem>]
```

Run `make` then `./derpgp`.

#### derpgp options

	-h,--help:		Show help/usage information.
	-i,--input:		ame of the file to use for input.
	-o,--output:		Name of the file to output source to.
	-v,--version:		Show version information.

## Libraries used:

* libtap ([zorgnax/libtap](https://github.com/zorgnax/libtap))
