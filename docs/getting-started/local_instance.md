---
layout: default
title: Running a local instance
parent: Getting started
nav_order: 2
permalink: /getting-started/local-instance/
---

# Local instance of ClusterFuzz
{: .no_toc}

You can run a local instance of ClusterFuzz to test core functionality. Note
that some features (like [crash] and [fuzzer statistics]) are disabled in local instances due to
lack of Google Cloud emulators.

- TOC
{:toc}

[crash]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#crash-statistics
[fuzzer statistics]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#fuzzer-statistics

---

## Running a local server

You can start a local server by running the following command:

```bash
# If you run the server for the first time or want to reset all data.
python butler.py run_server --bootstrap

# In all the other cases, do not use "--bootstrap" flag.
python butler.py run_server
```

It may take a few seconds to start. Once you see an output line like
`[INFO] Listening at: http://0.0.0.0:9000`, you can see the web interface by navigating to [http://localhost:9000](http://localhost:9000).

**Note:** The local instance may use ports [other than 9000](https://github.com/google/clusterfuzz/blob/master/src/local/butler/constants.py),
such as 9008, for things like uploading files. Your local
instance may break if the needed ports are unavailable, or if you can only access
some of the needed ports from your browser (for example, if you have port
forwarding or firewall rules when accessing from another host).

## Running a local bot instance

You can run a ClusterFuzz bot in your local instance by running the following command:

```bash
python butler.py run_bot --name my-bot /path/to/my-bot  # rename my-bot to anything
```

This creates a copy of the ClusterFuzz source under `/path/to/my-bot/clusterfuzz`
and uses it to run the bot. Most bot artifacts like logs, fuzzers,
and corpora are created inside the `bot` subdirectory.

If you plan to fuzz native GUI applications, we recommend you run this command
in a virtual framebuffer like [Xvfb](https://en.wikipedia.org/wiki/Xvfb).
Otherwise, you'll see GUI dialogs while fuzzing.

### Viewing logs

You can see logs on your local instance by running the following command:

```bash
cd /path/to/my-bot/clusterfuzz/bot/logs
tail -f bot.log
```

**Note:** Until you [set up your fuzzing jobs]({{ site.baseurl }}/setting-up-fuzzing/),
you'll see a harmless error in the logs: `Failed to get any fuzzing tasks`.

## Local Google Cloud Storage
We simulate [Google Cloud Storage] using your local filesystem. By default, this
is stored at `local/storage/local_gcs` in your ClusterFuzz checkout. 

You can override the default location by doing the following:
1. Use the `--storage-path` flag with the `run_server` command. 
2. Specify the same path using the `--server-storage-path` flag with the `run_bot`
command.

In the location you specify, objects are stored in `<bucket>/objects/<object path>` and
metadata is stored in `<bucket>/metadata/<object path>`.

[Google Cloud Storage]: https://cloud.google.com/storage/
