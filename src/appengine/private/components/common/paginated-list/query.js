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

if (!window.query) {
  let query = {};
  window.query = query;

  query.get = () => {
    return window.location.search.substring(1);
  };

  query.getParam = (key) => {
    let p = query.toObject(query.get(), [key]);
    return p[key];
  };

  query.parse = (str) => {
    str = str.trim();
    if (!str) { return {}; }

    let keysAndValues = str.split('&');
    let params = {};
    keysAndValues.forEach((keyAndValue) => {
      let pair = keyAndValue.split('=');
      params[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
    });

    return params;
  };

  query.compute = (params, keys) => {
    let keysAndValues = [];

    keys.forEach((key) => {
      let value = params[key];
      if (value) {
        keysAndValues.push(
            encodeURIComponent(key) + '=' + encodeURIComponent(value));
      }
    });

    return keysAndValues.sort().join('&');
  };

  query.toObject = (str, keys) => {
    let hash = query.parse(str);
    let returnedObj = {}
    keys.forEach((name) => {
      if (hash[name]) {
        returnedObj[name] = hash[name];
      }
    });

    return returnedObj;
  };
}
