# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Helpers for sending mail."""
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import From
from sendgrid.helpers.mail import HtmlContent
from sendgrid.helpers.mail import Mail
from sendgrid.helpers.mail import Subject
from sendgrid.helpers.mail import To

from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.metrics import logs


def send(to_email, subject, html_content):
  """Send email."""
  sendgrid_api_key = db_config.get_value('sendgrid_api_key')
  if not sendgrid_api_key:
    logs.log_warn('Skipping email as SendGrid API key is not set in config.')
    return

  from_email = db_config.get_value('sendgrid_sender')
  if not from_email:
    logs.log_warn('Skipping email as SendGrid sender is not set in config.')
    return

  message = Mail(
      from_email=From(str(from_email)),
      to_emails=To(str(to_email)),
      subject=Subject(subject),
      html_content=HtmlContent(str(html_content)))
  try:
    sg = SendGridAPIClient(sendgrid_api_key)
    response = sg.send(message)
    logs.log(
        'Sent email to %s.' % to_email,
        status_code=response.status_code,
        body=response.body,
        headers=response.headers)
  except Exception:
    logs.log_error('Failed to send email to %s.' % to_email)
