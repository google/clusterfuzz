// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


/**
 * parseError() parses an error from iron-ajax.
 */
function parseError(originalError) {
  if (!originalError) {
    // error is undefined because its request is aborted programmatically.
    return null;
  }

  let error = {};

  if (originalError.response && originalError.response.message) {
    error.message = originalError.response.message;
    error.traceDump = originalError.response.traceDump;
  } else {
    error.message = 'Unexpected error occurred.';
    error.traceDump = 'It might be a network failure. Please try again' +
        ' in a moment.\nIf the problem persists, please report to' +
        ' clusterfuzz-dev [at] chromium [dot] org.';
  }

  return error;
}

