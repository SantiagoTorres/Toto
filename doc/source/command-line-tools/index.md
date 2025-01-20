# Command Line Tools

in-toto provides various command line tools that you can use to generate,
consume, modify and verify in-toto metadata. Detailed usage instructions for
each tool, along with examples, are provided below.

```{admonition} Cryptographic Signatures

in-toto metadata is signed with cryptographic keys. The CLI accepts key files
in standard PEM format. See [in-toto#662](https://github.com/in-toto/in-toto/issues/662)
for details about key generation.
```

## Evidence Generation

```{toctree}
:maxdepth: 2

in-toto-run: generate signed link metadata <in-toto-run>
in-toto-record: generate signed link metadata in multiple steps <in-toto-record>
in-toto-match-products: match local artifacts against link metadata products <in-toto-match-products>
```

## Supply Chain Verification

```{toctree}
:maxdepth: 2

in-toto-verify: perform final product supply chain verification <in-toto-verify>
```

## Utilities

```{toctree}
:maxdepth: 2

in-toto-mock: mock in-toto-run <in-toto-mock>
in-toto-sign: sign/verify individual pieces of metadata <in-toto-sign>
```
