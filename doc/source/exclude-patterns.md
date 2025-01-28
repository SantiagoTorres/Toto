# Artifact Exclude Patterns

The optional argument `exclude_patterns` in the `in_toto_run` API, also used by
`--exclude` in the `in-toto-run` command line tool, applies
[pathspec](http://python-path-specification.readthedocs.io) to compile
[gitignore-style patterns](https://git-scm.com/docs/gitignore). Artifacts
(materials and products) matched by an exclude pattern are not recorded when
generating link metadata.

## Format Specification

- Single asterisks match everything except a slash.
- Question marks match any one character except a slash.
- Ranges of characters can be used in patterns using the `[]` notation (i.e.,
  `[a-z]`).
- A forward slash indicates a directory separator.
- A single `/` does not match any file.
- Separators at the beginning or middle (or both) of a pattern are relative to
  the current directory. Separators at the end of the pattern only match
  directories. (e.g., `/frotz` matches `frotz/` but not `doc/frotz`,
  `doc/frotz/` matches the `doc/frotz/` directory but not `a/doc/frotz/`;
  however `frotz/` matches `frotz/` and `a/frotz/`).
- To match an absolute path using a pattern, a single forward slash (`/`) at the
  beginning of the pattern is not sufficient. A single forward slash is used for
  relative roots rather than the "actual" root found in absolute paths. Using
  double forward slashes will get around this (i.e., `//<pattern>`).
- Leading double asterisks match any preceding path segments (e.g., `**/foo`
  matches file or directory `foo`, and `**/foo/bar` matches file or directory
  `bar` anywhere that is directly under directory `foo`).
- Trailing double asterisks match any succeeding path segments (e.g., `abc/**`
  matches all files inside directory `abc`).
- A slash followed by two consecutive asterisks and a slash matches path
  segments between two directories (e.g., `a/**/b` matches `a/b`, `a/x/b`,
  `a/x/y/b` and so on).
- A pattern ending with a slash will match all descendant paths. This is
  equivalent to `{pattern}/**`. If a pattern matches a directory, all files and
  subdirectories are also excluded.
- A hash serves as a comment, but it doesn't apply to this context. The hash can
  be escaped with a back-slash to match a literal hash (i.e., `\#`).
- An exclamation mark negates the rest of the pattern. Like the hash, this isn't
  particularly necessary for the context of exclude patterns. This can be
  escaped with a back-slash to match a literal exclamation mark (i.e., `\!`).

## References

- [`pathspec`](http://python-path-specification.readthedocs.io/)
- [`gitignore`](https://git-scm.com/docs/gitignore)
