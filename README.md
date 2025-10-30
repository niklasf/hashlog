hashlog
=======

When the use case is weird enough that existing tools don't fit perfectly ...
track and verify MD5/SHA1/SHA256 hashes of files in a local database.

Examples
--------

Compute and store hashes for some tablebase files, efficiently using multiple
hash algorithms in one pass:

```sh
hashlog add /mnt/op1/basemb/*_out --md5 --sha1 --sha256
```

Check against known hashes, that do not specify the directory where each
file is stored:

```sh
hashlog check /mnt/op1/basemb/k_*.md5 --prefix /mnt/op1/basemb/*_out
```

MD5 would have been good enough, but now we can confidently publish SHA1 or
SHA256 hashes as well:

```sh
cd /mnt/op1/basemb
hashlog export --sha1 *_out
```

Later, verify all recorded hashes, reading each file from disk:

```sh
hashlog verify
```

License
-------

GPLv3 or later, see the COPYING file.
