import github

from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.metrics import logs


TESTCASE_REPORT_URL = 'https://{domain}/testcase?key={testcase_id}'

MONORAIL_URL = (
    "https://bugs.chromium.org/p/oss-fuzz/detail?id={bug_information}")
OSS_FUZZ_ISSUE_URL = "https://github.com/google/oss-fuzz/issues/new"

GithubIssueTittleText = "OSS-Fuzz issue {bug_information}"

GithubIssueContentText = (
    "OSS-Fuzz has found a bug in this project. Please see "
    f"{TESTCASE_REPORT_URL}"
    "for details and reproducers."
    "\n\n"
    "This issue is mirrored from "
    f"{MONORAIL_URL} "
    "and will auto-close if the status changes there."
    "\n\n"
    "If you have trouble accessing this report, "
    f"please file an issue at {OSS_FUZZ_ISSUE_URL}."
    "\n")

GithubIssueCloseCommentText = ("OSS-Fuzz has closed this bug. Please see "
                               f"{MONORAIL_URL} "
                               "for details.")


def get_github_issue_title(testcase):
  """Generate the title of the issue"""
  return GithubIssueTittleText.format(bug_information=testcase.bug_information)


def get_github_issue_body(testcase):
  """Generate the body of the issue"""
  return GithubIssueContentText.format(
      domain=data_handler.get_domain(),
      testcase_id=testcase.key.id,
      bug_information=testcase.bug_information)


def get_github_issue_close_comment(testcase):
  """Generate the closing comment of the issue"""
  return GithubIssueCloseCommentText.format(
      bug_information=testcase.bug_information)


def get_github_access():
  """Get access to GitHub with the oss-fuzz personal access token"""
  token = db_config.get_value("oss_fuzz_robot_github_personal_access_token")
  if not token:
    logs.log_error("Unable to get oss-fuzz-robot's personal access token.")
    return None
  return github.Github(token)


def github_filing_enabled(testcase):
  """Check if the project YAML file requires to file a github issue."""
  require_github_issue = data_handler.get_value_from_job_definition(
      testcase.job_type, 'FILE_GITHUB_ISSUE', default='False')
  return require_github_issue.lower() == 'true'


def get_github_repo(testcase, github_access):
  """Get the GitHub repository to file the issue"""
  github_repo_url = data_handler.get_value_from_job_definition(
      testcase.job_type, 'MAIN_REPO', '')
  if not github_repo_url:
    logs.log_error("Unable to fetch the MAIN_REPO URL from job definition.")
    return None
  github_repo_name = github_repo_url.removeprefix('https://github.com/')

  try:
    target_repo = github_access.get_repo(github_repo_name)
  except github.UnknownObjectException as e:
    logs.log_error(f"Unable to locate GitHub repository "
                   f"named {github_repo_name} from URL: {github_repo_url}.")
    target_repo = None
  return target_repo


def file_issue_to_github(github_repo, testcase):
  """Post the issue to the Github repo of the project."""
  github_issue_title = get_github_issue_title(testcase)
  github_issue_body = get_github_issue_body(testcase)
  return github_repo.create_issue(
      title=github_issue_title, body=github_issue_body)


def update_testcase_properties(testcase, github_repo, github_issue):
  """Update the github-related properties in the FiledBug entity."""
  testcase.github_repo_id = github_repo.id
  testcase.github_issue_num = github_issue.number


def file_github_issue(testcase):
  """File a github issue to the GitHub repo of the project"""
  if not github_filing_enabled(testcase):
    return

  github_access = get_github_access()
  if not github_access:
    logs.log_error("Unable to access github account and file the issue.")
    return
  github_repo = get_github_repo(testcase, github_access)
  if not github_repo:
    logs.log_error("Unable to locate github repository and file the issue.")
    return
  github_issue = file_issue_to_github(github_repo, testcase)
  update_testcase_properties(testcase, github_repo, github_issue)


def issue_recorded(testcase):
  """Verify the issue has been filed."""
  return hasattr(testcase, 'github_repo_id') \
         and testcase.github_repo_id is not None \
         and hasattr(testcase, 'github_issue_num') \
         and testcase.github_issue_num is not None


def get_github_issue(testcase, github_access):
  """Locate the issue of the testcase."""
  github_repo_id = testcase.github_repo_id
  github_issue_num = testcase.github_issue_num
  try:
    github_repo = github_access.get_repo(github_repo_id)
  except github.UnknownObjectException as e:
    logs.log_error("Unable to locate the github repository "
                   f"id {github_repo_id}.")
    return None

  try:
    target_issue = github_repo.get_issue(github_issue_num)
  except github.UnknownObjectException as e:
    logs.log_error("Unable to locate the github issue "
                   f"number {github_issue_num}.")
    target_issue = None
  return target_issue


def close_issue_with_comment(testcase, github_issue):
  """Generate closing comment, comment, and close the GitHub issue."""
  issue_close_comment = data_handler.get_github_issue_close_comment(testcase)
  github_issue.create_comment(issue_close_comment)
  github_issue.edit(state='closed')


def close_github_issue(testcase):
  """Close the issue on github, when the same issue is closed on Monorail."""
  if not issue_recorded(testcase):
    return
  github_access = get_github_access()
  if not github_access:
    logs.log_error("Unable to access github account and close the issue.")
    return
  github_issue = get_github_issue(testcase, github_access)
  if not github_issue:
    logs.log_error("Unable to locate and close the issue.")
    return
  close_issue_with_comment(testcase, github_issue)
  logs.log(f"Closed issue number {testcase.github_issue_num} "
           f"in GitHub repository {testcase.github_repo_id}.")
