---
layout: default
title: Setting up bots
parent: Production setup
permalink: /production-setup/setting-up-bots/
nav_order: 4
---

# Setting up bots
This page walks you through the process of setting up bots on each of the
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

By default, the ClusterFuzz configuration file creates 1 regular Linux bot and 2
[preemptible] Linux bots on [Google Compute Engine]. You can configure them by
following the instructions provided [here](#google-compute-engine-cluster) and
[here](#google-compute-engine-instance-template).

We recommend that you use preemptibles for most of your bots because they
are much cheaper and perform almost as well. You still need some regular
bots (non-preemptibles) to execute other tasks, such as the tasks that run after
a crash is discovered (minimization, regression, etc).

### Windows

Windows is a supported platform for fuzzing. The only [sanitizer] supported on
Windows is [AddressSanitizer]. The only [fuzzing engine] supported on Windows
is [libFuzzer].

By default, ClusterFuzz configuration files do not enable any Windows bots. You
can enable them easily by following the instructions provided
[here](#google-compute-engine-cluster) and
[here](#google-compute-engine-instance-template).

You also need to [set a password](#windows-password-setup) for the administrator
account on the bots.

### macOS

Mac is a supported platform for fuzzing. The sanitizers supported on Mac are
[AddressSanitizer], [LeakSanitizer], [UndefinedBehaviorSanitizer]
and [ThreadSanitizer]. The only [fuzzing engine] supported on Mac is
[libFuzzer].

Mac is not a supported platform on [Google Compute Engine], so you would need to
run it on physical hardware or some sort of virtualization running on top of it.

Below are the steps to set up and run ClusterFuzz:

* Create a service account key following the instructions provided
[here](https://cloud.google.com/docs/authentication/getting-started).
  * Choose "Compute Engine" service account type.
  * Choose "JSON" key type.
* Securely transfer the downloaded key file to the macOS computer.
* Run the provided startup script.

```bash
export CLOUD_PROJECT_ID=<your project id>
export CONFIG_DIR=/path/to/myconfig
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
export INSTALL_DIRECTORY=/path/where/to/install/clusterfuzz-and-dependencies/to
$CONFIG_DIR/bot/setup/mac.bash
```

## Configuration

### Google Compute Engine Cluster

You can configure a cluster of bots on [Google Compute Engine] by modifying the
configuration file `$CONFIG_DIR/gce/clusters.yaml`. The clusters definition is
in the `<your project id>/clusters` attribute of this yaml file. Below are
example definitions for [preemptible] and regular Linux bots:

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

You can configure the bots by first uncommenting the cluster definition,
and then changing the values in the `gce_zone` (e.g. `us-central1-a`) and
`instance_count` attributes. You can also create your own
[instance template](#google-compute-engine-instance-template)
and then define a new cluster section here.

**Note**:
* Make sure to [deploy] new changes. Otherwise, they will not be reflected in
production.

### Google Compute Engine Instance Template

You can read more about instance templates
[here](https://cloud.google.com/compute/docs/instance-templates). Instance
templates define the properties of a bot (e.g. source image, disk space, network
config). They are defined after the clusters configuration section in
`$CONFIG_DIR/gce/clusters.yaml`. Below is an example for a regular Linux bot:


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
            value: gcr.io/clusterfuzz-images/base:c44bf3f-201902112042
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

[build]: {{ site.baseurl }}/production-setup/build-pipeline/
[deploy]: #deploying-new-changes
[fuzzing engine]: {{ site.baseurl }}/reference/glossary/#fuzzing-engine
[job]: {{ site.baseurl }}/reference/glossary/#job-type
[preemptible]: {{ site.baseurl }}/architecture/#fuzzing-bots
[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer
[AddressSanitizer]: https://clang.llvm.org/docs/AddressSanitizer.html
[LeakSanitizer]: https://clang.llvm.org/docs/LeakSanitizer.html
[MemorySanitizer]: https://clang.llvm.org/docs/MemorySanitizer.html
[UndefinedBehaviorSanitizer]: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
[ThreadSanitizer]: https://clang.llvm.org/docs/ThreadSanitizer.html
[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[Google Compute Engine]: https://cloud.google.com/compute
