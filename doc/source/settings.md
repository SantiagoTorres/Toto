# Settings

Default values for some in-toto CLI/API arguments are defined in global variables of the
`in_toto.settings` module. Historically, configuration required modifying these
globals directly in source code or at runtime. This method is discouraged. Instead,
CLI/API arguments should be used.

```{note}

The global `DEBUG` can only be configured directly.
```
