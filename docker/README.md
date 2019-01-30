# Docker Build Instructions

## Local testing

You can build an image locally as:

```bash
cd /path/to/image/dir
docker build .
```

where `/path/to/image/dir` is any image sub-directory in this directory that contains a
'Dockerfile'.

## Production

To build all images on container builder, run:

```bash
./build_on_container_builder.sh
```

Note that your checkout needs to be on the latest deployed commit.
You also need to have access to the `clusterfuzz-images` project.
