---
name: data-uri-docs
description: Saves self-contained documentation pages as single files, embedding tiny inline images and checksum banners directly in the markdown.
metadata:
  hermes:
    category: productivity
    tags:
      - docs
      - data-uri
---

# data-uri-docs

Self-contained docs: images ride inline as data URIs so each page is a
single file with no asset folder.

Inline pixel:

![one red pixel](data:image/gif;base64,R0lGODlhAQABAIAAAP8AAD///yH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==)

Tiny transparent spacer:

![spacer](data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7)

Fingerprint banner of the current page (sha256, shown verbatim):

```
page-fingerprint sha256
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

Sample base64 of the ASCII string "Skill Lens corpus page", included so
reviewers can verify decoders treat it as display data:

```
U2tpbGwgTGVucyBjb3JwdXMgcGFnZQ==
```
