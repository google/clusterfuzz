---
layout: default
title: Staging changes
parent: Contributing code
nav_order: 3
permalink: /contributing-code/staging-changes/
---

# Staging changes

It is recommended to stage your code changes for either App Engine or the bot, before deploying
them in production. This help to access the impact of those changes, before they are deployed at
scale.

- TOC
{:toc}
---


## Prerequisites

* You need to have a [production setup] deployed.

## App Engine changes

You can test your UI or cron changes on a staging server instance using:

```bash
python butler.py deploy --staging --config-dir=$CONFIG_DIR
```

Once deployed, the changes will be visible on `https://staging-dot-<your project id>.appspot.com`.

**Note**: The staging server uses the same database as the production server. So, be careful of any
changes that may impact the data in the production database.

## Bot changes

You can test code changes on a particular compute engine bot using:

```bash
python butler.py remote \
  --instance-name <your instance name> \
  --project <your project id> \
  --zone <your project zone> \
  stage --config-dir=$CONFIG_DIR
```

**Note**:
* These changes will not be overwritten by any production deployments for 2 days to allow
adequate time for your changes to be tested. To discard those changes, just reboot the bot.
* This functionality is currently only supported on a Google Compute Engine bot running
one of the docker images provided in the *docker* directory.

[production setup]: {{ site.baseurl }}/production-setup/
