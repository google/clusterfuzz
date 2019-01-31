---
layout: default
title: Setting up bots
parent: Production setup
permalink: /production-setup/setting-up-bots/
nav_order: 4
---

# Setting up bots
This page walks you through the process of setting up bots on one of the supported platforms:
**Linux**, **Windows** and **macOS**.

- TOC
{:toc}
---

## Linux

Linux is the preferred platform for fuzzing because of its comprehensive support for all
[sanitizer] and [fuzzing engine] types.

It is recommended to use each sanitizer its own [build] and [job] definition (except LSan), as
there are performance and bug finding efficiency issues with combining them.

By default, ClusterFuzz configuration files in `$CONFIG_DIR/gce/clusters.yaml` define 1 Linux
regular bot and 2 [preemptible] bots on Google Compute Engine. These can be configured by
changing the `instance_count` in the cluster definition as shown below:
```bash
# Regular bots run all task types (e.g fuzzing, minimize, etc).
clusterfuzz-linux:
  gce_zone: gce-zone
  instance_count: 1
  instance_template: clusterfuzz-linux
  distribute: False

# Pre-emptible bots must have '-pre-' in name. They only run fuzzing tasks.
clusterfuzz-linux-pre:
  gce_zone: gce-zone
  instance_count: 2
  instance_template: clusterfuzz-linux-pre
  distribute: False
```

It is recommended to have the majority of your bots as preemptibles since they are much cheaper
and they do not impact the production workload in any significant way (since only fuzzing tasks
are executed there). You still need some regular bots (non-preemtible) to execute other tasks
e.g. post-operation tasks after a crash is discovered like minimization, regression, etc.

You can customize the properties of these bot as well. This is done by modifying the instance
template of the bot in the same file. For example, you can configure the size of the disk using
`diskSizeGb` attribute. Read more about instance templates
[here](https://cloud.google.com/compute/docs/instance-templates/).

```bash
instance_templates:
  - name: clusterfuzz-linux
    description: '{"version": 1}'
    properties:
      machineType: n1-standard-1
      disks:
        - boot: true
          autoDelete: true
          initializeParams:
            sourceImage: projects/cos-cloud/global/images/family/cos-stable
            diskSizeGb: 100
  ...
```

**NOTE**:
* After making a change in the instance template, you must increment the version by 1.
* Make sure to [deploy] new changes. Otherwise, they will not reflect in production.
* Once deployed, bots are automatically created via a cron that runs every 30 minutes.
  You can manually force it by visiting the `Cron jobs` page
  [here](https://console.cloud.google.com/appengine/cronjobs) and then running the
  `/manage-vms` cron job.

## Windows

Windows is a supported platform for fuzzing. Currently, only [AddressSanitizer] [sanitizer]
and [libFuzzer] [fuzzing engine] are available for use on this platform.

By default, ClusterFuzz configuration files in `$CONFIG_DIR/gce/clusters.yaml` do not
enable any Windows bots. You can enable them easily by un-commenting any of the
`clusterfuzz-windows-*` cluster definitions.

```bash
clusterfuzz-windows:
  gce_zone: gce-zone
  instance_count: 1
  instance_template: clusterfuzz-windows
  distribute: False

clusterfuzz-windows-pre:
  gce_zone: gce-zone
  instance_count: 1
  instance_template: clusterfuzz-windows-pre
  distribute: False
```

Similar to [Linux](#linux) bots, you can configure any of the instance templates to suit your needs.

In addition to the steps above, you also need to set the admin password in the `windows-password`
project metadata attribute. The password must satisfy the windows password policy requirements.

```bash
$ gcloud compute project-info add-metadata \
    --metadata-from-file=windows-password=/path/to/password-file --project=$CLOUD_PROJECT_ID
```
This allows you to rdp into any of your windows bot(s) with the `clusterfuzz` username (admin) and
your configured password.

## Mac

Mac is a supported platform for fuzzing. Currently, only [AddressSanitizer], [LeakSanitizer],
[UndefinedBehaviorSanitizer] and [ThreadSanitizer] [sanitizer] are available on this platform.
For [fuzzing engine], only [libFuzzer] is available on this platform.

TODO: Add setup instructions

[build]: {{ site.baseurl }}/production-setup/build-pipeline
[deploy]: {{ site.baseurl }}/production-setup/clusterfuzz/#deploying-new-changes
[fuzzing engine]: {{ site.baseurl }}/reference/glossary/#fuzzing-engine
[job]: {{ site.baseurl }}/reference/glossary/#job-type
[preemptible]: {{ site.baseurl }}/architecture/#bots
[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer
[AddressSanitizer]: https://clang.llvm.org/docs/AddressSanitizer.html
[LeakSanitizer]: https://clang.llvm.org/docs/LeakSanitizer.html
[MemorySanitizer]: https://clang.llvm.org/docs/MemorySanitizer.html
[UndefinedBehaviorSanitizer]: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
[ThreadSanitizer]: https://clang.llvm.org/docs/ThreadSanitizer.html
[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
