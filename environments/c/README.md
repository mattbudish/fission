# Fission: C Environment

This is the C environment for Fission.

It's a Docker image containing a C runtime, along with a dynamic loader.

## Build this image

```
docker build -t USER/c-runtime . && docker push USER/c-runtime
```

Note that if you build the runtime, you must also build the c-builder
image, to ensure that it's at the same version of c:

```
cd builder && docker build -t USER/c-builder . && docker push USER/c-builder
```

## Using the image in fission

You can add this customized image to fission with "fission env
create":

```
fission env create --name c --image USER/c-runtime --builder USER/c-builder --version 2
```

Or, if you already have an environment, you can update its image:

```
fission env update --name c --image USER/c-runtime --builder USER/c-builder
```

After this, fission functions that have the env parameter set to the
same environment name as this command will use this environment.

## Creating functions to use this image

See the [examples README](examples/c/README.md).
