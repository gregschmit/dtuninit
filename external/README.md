# External Libraries

This directory contains external libraries used by this project.

The sources are included as git submodules, when possible. The dependencies are built by our
Makefile (either a custom script or invoking the library's build system) and the artifacts are
copied into this directory. This can include headers, object files, and static/shared libraries.

When convenient, we should prefer linking with an object file rather than a static/shared library.
