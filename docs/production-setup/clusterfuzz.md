---
layout: default
title: ClusterFuzz
parent: Production setup
permalink: /production-setup/clusterfuzz/
nav_order: 1
---

# Setting up a production project
This document walks you through the process of setting up a production project
using ClusterFuzz.

- TOC
{:toc}

---

## Prerequisites

Make sure to go through
[Prerequisites]({{ site.baseurl }}/getting-started/prerequisites/) page first.

## Create a new Google Cloud project

Follow [these instructions](https://cloud.google.com/resource-manager/docs/creating-managing-projects)
to create a new Google Cloud Project.

Verify that your project is successfully created using

```bash
gcloud projects describe <your project id>
```

Export the project id in environment for later use:

```bash
export CLOUD_PROJECT_ID=<your project id>
```

If you're new to Google Cloud you may be eligible for [trial credit].

[trial credit]: https://cloud.google.com/free/docs/gcp-free-tier#free-trial

## Enable Firebase
1. Follow [these instructions](https://cloud.google.com/appengine/docs/standard/python3/building-app/adding-firebase)
   to add Firebase to the Google Cloud project you just created. This will be
   used for authentication and should not incur any additional charges.

2. In the [Firebase console], go to the **Auth** section and enable "Google" as
   a Sign-in provider.

3. In the same section, add the domains you plan on using to the "Authorized
   domains" list. The default domain for App Engine looks like
   `<your project id>.appspot.com`.

### Web API Key
To obtain a web API key,
1. Go to the [Firebase console] and select your project.
2. From the project overview page, click **Add Firebase to your web app** to
   display the customized code snippet.
3. Copy the `apiKey` value, and export it like so:

```bash
export FIREBASE_API_KEY=<your api key>
```

[Firebase console]: https://console.firebase.google.com/

## Create OAuth credentials
Follow [these instructions](https://developers.google.com/identity/protocols/OAuth2InstalledApp#creatingcred)
to create OAuth credentials for our project setup script. Choose
`OAuth client ID` credential type. When prompted for an application type, choose
`Desktop app`. You may also need to fill in the application name on "OAuth
consent screen" tab, enter any name of your choice, e.g. `MyClusterFuzz`.

Download these credentials as JSON and place it somewhere safe. Export the path
for later use:

e.g.

```bash
export CLIENT_SECRETS_PATH=/path/to/your/client_secrets.json
```

## Run the project setup script
Now you can run our project setup script to automate the process of setting up
a production instance of ClusterFuzz.

This script also creates a config directory for you, which contains some default
settings for your deployment and can be later updated.

```bash
mkdir /path/to/myconfig  # Any EMPTY directory outside the ClusterFuzz source repository.
export CONFIG_DIR=/path/to/myconfig
python butler.py create_config --oauth-client-secrets-path=$CLIENT_SECRETS_PATH \
  --firebase-api-key=$FIREBASE_API_KEY --project-id=$CLOUD_PROJECT_ID $CONFIG_DIR
```

This can take a few minutes to finish, so please be patient. The script also
performs a test deployment to verify that the project has been successfully set
up.

Check out the configuration yaml files in `/path/to/myconfig` directory and
change the defaults to suit your use cases. Some common configuration items
include:
* Change the default project name using `env.PROJECT_NAME` attribute in
  `project.yaml`.
* Add access for all users of a domain using `whitelisted_domains` attribute in
  `gae/auth.yaml`.
* Use a custom domain for hosting (instead of `appspot.com`) using `domains`
  attribute in `gae/config.yaml`.

It's recommended to check your `/path/to/myconfig` directory into your own
version control to track your configuration changes and to prevent loss.

## Verification

To verify that your project is successfully deployed.

* Verify that your application is accessible on
  `https://<your project id>.appspot.com`. If you see an error on missing
  datastore indexes, this may take some time to be generated after the
  deployment finished. You can check the status
  [here](https://appengine.google.com/datastore/indexes).

* Verify that the bots are successfully created using the instructions
  [here]({{ site.baseurl }}/production-setup/setting-up-bots#google-compute-engine-bots).
  The defaults are 1 regular linux bot and 2
  [preemptible](https://cloud.google.com/preemptible-vms/) linux bots on Google
  Compute Engine.

## Deploying new changes
Now that the initial setup is complete, you may deploy further changes by
running:

```bash
python butler.py deploy --config-dir=$CONFIG_DIR --prod --force
```

## Configuring number of bots
See this [page]({{ site.baseurl }}/production-setup/setting-up-bots/) for
instructions to set up the bots.

Once you make changes to the `clusters.yaml` file, you must re-deploy by
following the [previous section](#deploying-new-changes). An App Engine cron job
will periodically read the contents of this file and create or delete new
instances as necessary.

### Other cloud providers
Note that bots do not have to run on Google Compute Engine. It is possible to
run your own machines or machines with another cloud provider. To do so, those
machines must be running with a [service account] to access the necessary
Google services such as Cloud Datastore and Cloud Storage.

We provide [Docker images] for running ClusterFuzz bots.

[Google Compute Engine]: https://cloud.google.com/compute/
[service account]: https://cloud.google.com/iam/docs/creating-managing-service-account-keys
[Docker images]: https://github.com/google/clusterfuzz/tree/master/docker
[preemptible]: {{ site.baseurl }}/architecture/#fuzzing-bots
