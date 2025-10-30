hashlog
=======

When the use case is weird enough that existing tools don't fit perfectly ...
track and verify MD5/SHA1/SHA256 hashes of files.

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

Export hashes of the stored files, relative to the current directory, for
publishing:

```sh
cd /mnt/op1/basemb
hashlog export --sha1 *_out
```

Verify all recorded hashes, reading each file from disk:

```sh
hashlog verify
```
