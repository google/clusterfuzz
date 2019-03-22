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

if (!window.storage) {
  let storage = {};
  window.storage = storage;

  storage.save = (key, data) => {
    // TODO(tanin): limit the number of entries by deleting the earliest
    // items. For now, let's hope no one uses the page intensively until
    // it exceeds the storage quota.
    try {
      window.localStorage.setItem(key, JSON.stringify(data))
    } catch (e) {
      console.log('localStorage.setItem(..) failed.', e);
    }
  };

  storage.get = (key) => {
    try {
      let data = window.localStorage.getItem(key);

      if (data) {
        return JSON.parse(data);
      } else {
        return null;
      }
    } catch (e) {
      console.log('localStorage.getItem(..) failed.', e);
      return null;
    }
  };

  storage.clear = () => {
    try {
      window.localStorage.clear();
    } catch (e) {
      console.log('localStorage.clear(..) failed.', e);
    }
  };
}
