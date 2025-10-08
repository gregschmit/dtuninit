# Exteral Libraries

This directory contains external libraries used by `dtuninit`.

The sources are included as git submodules, when possible. The dependencies are built by our
Makefile (either a custom script or invoking the library's build system) and the artifacts are
copied into this directory. This typically includes an object file and a header file.

External libraries should probably always be built statically.
