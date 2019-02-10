---
layout: default
title: Running a local instance
parent: Getting started
nav_order: 2
permalink: /getting-started/local-instance/
---

# Local instance of ClusterFuzz
You can run a local instance of ClusterFuzz to test core functionality. Note
that some features (e.g. [crash] and [fuzzer statistics]) are disabled to due to
lack of Google Cloud emulators.

- TOC
{:toc}

[crash]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#crash-statistics
[fuzzer statistics]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#fuzzer-statistics

---

## Running a local server

```bash
# If you run the server for the first time or want to reset all data.
python butler.py run_server --bootstrap

# In all the other cases, do not use "--bootstrap" flag.
python butler.py run_server
```

This may take a few seconds to start. Once you see output line like
`INFO <timestamp> admin_server.py:<num>] Starting admin server`, you should be able to navigate to
[http://localhost:9000](http://localhost:9000) to view the web interface.

## Running a local bot instance

```bash
python butler.py run_bot --name my-bot /path/to/my-bot  # rename my-bot to anything
```

This creates a copy of ClusterFuzz source under `/path/to/my-bot/clusterfuzz`
and runs the bot using it. Most of the bot artifacts like logs, fuzzers,
corpora, etc are created inside the `bot` subdirectory.

If you plan to fuzz native GUI applications, it is advisable to run this command
in a virtual framebuffer (e.g. [Xvfb](https://en.wikipedia.org/wiki/Xvfb)).
Otherwise, you will see GUI dialogs while fuzzing and will be unable to use the
machine with ease.

### Viewing logs
```bash
cd /path/to/my-bot/clusterfuzz/bot/logs
tail -f bot.log
```

Until you [set up the fuzzing jobs]({{ site.baseurl }}/setting-up-fuzzing/),
you will see a harmless error in the logs - `Failed to get any fuzzing tasks`.

## Local Google Cloud Storage
We simulate [Google Cloud Storage] using your local filesystem. By default, this
is stored at `local/storage/local_gcs` in your ClusterFuzz checkout. You can
override it using `--storage-path` when running `run_server` command and then
specifying the same path using `--server-storage-path` when running `run_bot`
command.

Under this location, objects are stored in `<bucket>/objects/<object path>` and
metadata is stored in `<bucket>/metadata/<object path>`.

[Google Cloud Storage]: https://cloud.google.com/storage/
