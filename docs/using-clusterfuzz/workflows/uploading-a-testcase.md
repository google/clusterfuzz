---
layout: default
title: Uploading a testcase
permalink: /using-clusterfuzz/workflows/uploading-a-testcase/
nav_order: 4
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Uploading a testcase

You may often have a testcase that you want to run against your latest production build to check if
it crashes. ClusterFuzz provides the `Upload Testcase` page for this purpose, which can give details
about the crash, e.g. crash stacktrace, when was it introduced, etc.

- TOC
{:toc}

---

## Upload new testcase

To upload a new testcase:

1. Click the "UPLOAD" button.
2. Archive your testcase locally.
   1. If your testcase is a single file, you can upload as-is.
   2. If your testcase consists of multiple files:
     - Name the *main file* that the app runs to contain **run** in its name.
     - Bundle all the files in an archive. Supported archive formats include *zip* and *tar* formats.
     - **Exception**: If you want to test multiple testcases at once, you don't
       need to rename them.  Just bundle them in an archive, and select **Test
       every file in archive independently** checkbox in the form.

3. Click the "Choose File" button and provide the testcase archive in the file chooser dialog.
4. Select a **Job**. This provides information of which build or application to
   run this testcase against.
5. If you selected a fuzzing engine job in last step (e.g. *libFuzzer*, *AFL*),
   you would need to provide the name of the *fuzz target* to use. This is
   required as an application build can contain multiple fuzz target binaries.
6. Provide values for any of the other optional fields in the form. Examples:
     1. You can provide a *Commit Position* / *Revision* to run it against a
        particular [revision].  This is usually used to check a crash against an
        older version of the application.
     2. If you want your testcase to be served from a http server, you can check
        the **Load testcase from HTTP server.** checkbox.
7. Click the "CREATE" button.

## Check status

Once you upload a new testcase, you will be redirected to the `Testcase Details` page. This page
auto-refreshes every *5 minutes* to provide the latest results. At first, it tries to find if the
testcase results in a crash or not. If it does not, it sets the status as **Unreproducible**. 
Otherwise if it does crash, then it starts with first updating the crash parameters in the
*Overview** section and crash stacktrace in the **Crash Stacktrace** section. Then, it tries the
other tasks such as testcase [minimization], finding the [regression range], etc.

Please be patient to wait on the results. The speed of the results will depend on the availability
of the next bot(s).

[revision]: {{ site.baseurl }}/reference/glossary/#revision
[minimization]: {{ site.baseurl }}/reference/glossary/#minimization
[regression range]: {{ site.baseurl }}/reference/glossary/#regression-range
