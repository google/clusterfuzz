---
layout: default
title: Setting up bots
parent: Production setup
permalink: /production-setup/setting-up-bots/
nav_order: 4
---

# Setting up bots
This page walks you through the process of setting up bots on one of the
supported platforms: **Linux**, **Windows** and **macOS**.

- TOC
{:toc}
---

## Platforms

### Linux

Linux is the preferred platform for fuzzing because of its comprehensive support
for all [sanitizer] and [fuzzing engine] types.

It is recommended to use each sanitizer its own [build] and [job] definition
(except [LeakSanitizer]), as there are performance and bug finding efficiency
issues with combining them.

By default, ClusterFuzz configuration file creates 1 Linux regular bot and 2
[preemptible] bots on [Google Compute Engine]. You can configure them by
following the instructions provided [here](#google-compute-engine-cluster) and
[here](#google-compute-engine-instance-template).

It is recommended to have the majority of your bots as preemptibles since they
are much cheaper and do not impact the production workload in any significant
way (since only fuzzing tasks are executed there). You still need some regular
bots (non-preemptibles) to execute other tasks e.g. post-operation tasks after a
crash is discovered like minimization, regression, etc.

### Windows

Windows is a supported platform for fuzzing. Currently, only
[AddressSanitizer] ([sanitizer]) and [libFuzzer] ([fuzzing engine]) are
available for use on this platform.

By default, ClusterFuzz configuration files do not enable any Windows bots. You
can enable them easily by following the instructions provided
[here](#google-compute-engine-cluster) and
[here](#google-compute-engine-instance-template).

You also need to [set a password](#windows-password-setup) for the administrator
account on the bots.

### macOS

Mac is a supported platform for fuzzing. Currently, only [AddressSanitizer],
[LeakSanitizer], [UndefinedBehaviorSanitizer] and [ThreadSanitizer] [sanitizer]
are available on this platform. For [fuzzing engine], only [libFuzzer] is
available on this platform.

Mac is not a supported platform on [Google Compute Engine], so you would need to
run it on physical hardware or some sort of virtualization running on top of it.

Following are the steps to setup and run ClusterFuzz:

* Create a service account key file using the steps provided
[here](https://cloud.google.com/docs/authentication/getting-started).
* Run the provided startup script.

```bash
export CLOUD_PROJECT_ID=<your project id>
export CONFIG_DIR=/path/to/myconfig
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
$CONFIG_DIR/bot/setup/mac.bash
```

## Configuration

### Google Compute Engine Cluster

You can configure a cluster of bots on [Google Compute Engine] by modifying the
configuration file `$CONFIG_DIR/gce/clusters.yaml`. The clusters definition is
in the `<your project id>/clusters` attribute of this yaml file. An example
definition for linux [preemptible] and regular bot is:

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

You can modify the number of bots by first uncommenting the cluster definition,
and then changing the value in the `instance_count` attribute. You can also
create your own [instance template](#google-compute-engine-instance-template)
and then define a new cluster section here.

**Note**:
* Make sure to [deploy] new changes. Otherwise, they will not be reflected in
production.

### Google Compute Engine Instance Template

You can read more about instance templates
[here](https://cloud.google.com/compute/docs/instance-templates). Instance
templates define the properties of a bot (e.g. source image, disk space, network
config). They are defined after the clusters configuration section in
`$CONFIG_DIR/gce/clusters.yaml`. An example for a linux regular bot is:


```aidl
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
            diskType: pd-standard
      metadata:
        items:
          - key: docker-image
            value: gcr.io/clusterfuzz-images/base:4e159c4-201812210404
          - key: user-data
            value: file://linux-init.yaml
      serviceAccounts:
        - email: my-project-id-service-account-email
          scopes:
            - https://www.googleapis.com/auth/cloud-platform
            - https://www.googleapis.com/auth/prodxmon
      networkInterfaces:
        - network: global/networks/default
          accessConfigs:
            - type: ONE_TO_ONE_NAT
              name: 'External NAT'
```

For example, you can configure the size of the disk using `diskSizeGb`
attribute.

**Note**:
* After making a change in the instance template, you must increment the version
by 1.
* Make sure to [deploy] new changes. Otherwise, they will not be reflected in
production.

### Windows password setup

Before enabling windows bots on [Google Compute Engine], you need to set the
administrator password in the `windows-password` metadata attribute. The
password must satisfy the windows password policy requirements. To set it, run:

```bash
gcloud compute project-info add-metadata \
  --metadata-from-file=windows-password=/path/to/password-file --project=$CLOUD_PROJECT_ID
```

This allows you to connect via remote desktop into your windows bots with the
`clusterfuzz` username (admin) and your configured password.

### Deploying new changes

Read the instructions
[here]({{ site.baseurl }}/production-setup/clusterfuzz/#deploying-new-changes)
to deploy new changes.

## Verification

### Google Compute Engine bots

Once deployed, bots are automatically created via an App Engine cron task that
runs every *30 minutes*. For faster results, you can manually force it by
visiting the `Cron jobs` page
[here](https://console.cloud.google.com/appengine/cronjobs) and running the
`/manage-vms` cron job.

After the cron job finishes, check this
[page](https://console.cloud.google.com/compute/instanceGroups/list) to ensure
that all instances are created for this particular
[instance group](#google-compute-engine-cluster).

If you see a spinning circle next to the instance group, for longer than a
few minutes, it can indicate that an error occurred. You can click the instance
group name to see the error message (e.g. insufficient resource quota).

**Note**: The default quota for compute resources such as "CPUs",
"In-use IP addresses" and "Persistent Disk Standard (GB)" might be
insufficient for your fuzzing cluster needs. You can check your
current quota [here](https://console.cloud.google.com/iam-admin/quotas)
and request more resources as needed.

### Non-Google Compute Engine bots

These bots should start within a minute after the startup script finishes
execution (e.g. `$CONFIG_DIR/bot/setup/mac.bash` for macOS).

You can verify the bots started by checking that their hostnames show up on
the *Bots* page.

[build]: {{ site.baseurl }}/production-setup/build-pipeline
[deploy]: #deploying-new-changes
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
[Google Compute Engine]: https://cloud.google.com/compute
