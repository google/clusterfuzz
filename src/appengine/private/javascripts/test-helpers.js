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

window.jsonHeaders = {'Content-Type': 'application/json'};
window.errorResponse = JSON.stringify({
  message: "RandomError",
  traces: ["trace"]
});
window.noop = () => {};


window.wait = () => {
  return new Promise((resolve) => {
    window.setTimeout(resolve, 1);
  });
};


window.makeTap = (panel) => {
  const selectAll = makeSelectAll(panel);

  return (selector, index=0) => {
    MockInteractions.tap(selectAll(selector)[index]);
  };
};


window.suite2 = (name, bodyFn) => {
  suite(name, () => {
    const $ = {};

    setup(() => {
      $.panel = fixture('panel');
      $.tap = makeTap($.panel);
      $.select = makeSelect($.panel);
      $.selectAll = makeSelectAll($.panel);
      $.slotSelect = makeSlotSelect($.panel);
      $.slotSelectAll = makeSlotSelectAll($.panel);
      $.server = sinon.fakeServer.create();
    });

    bodyFn($);
  });
};


/**
 * A helper for declaring a test. This avoids multiple nested Promise.then(..)
 * and flush(..). See crbug.com/649197 why we need this helper.
 *
 * @param {string} name the test name that is passed to test(..).
 * @param {Array of functions} ...stepFns a list of functions, each of which is
 *     invoked and waited for its optional returned promise, sequentially.
 *
 * For example, test2('name', fn0, fn1, fn2), where fn1 returns a Promise, is
 * equivalent to:
 *     test('name', (done) => {
 *       fn0();
 *       flush(() => {
 *         let promise = fn1();
 *
 *         promise.then(() => {
 *           flush(() => {
 *             fn2();
 *             done();
 *           });
 *         });
 *       });
 *     });
 */
window.test2 = (name, ...stepFns) => {
  let callFunc = (fns, done) => {
    let firstFn = fns.shift();
    let maybePromise = firstFn();

    let nextStep = () => {
      if (fns.length == 0) {
        done();
      } else {
        flush(() => {
          callFunc(fns, done);
        });
      }
    };

    if (maybePromise && 'function' == typeof maybePromise.then) {
      maybePromise
        .then(wait, wait)
        .then(nextStep);
    } else {
      nextStep();
    }
  };

  test(name, (done) => {
    callFunc(stepFns, done);
  });
};


window.makeSelect = (panel) => {
  return (selector) => {
    return panel.shadowRoot.querySelector(selector);
  };
};


window.makeSelectAll = (panel) => {
  return (selector) => {
    return panel.shadowRoot.querySelectorAll(selector);
  };
};

window.makeSlotSelect = (panel) => {
  return (slotSelector, selector) => {
    let nodes = panel.shadowRoot.querySelector('slot' + slotSelector)
        .assignedNodes({flatten: true});
    if (!selector) {
      return nodes[0];
    }

    for (node of nodes) {
      if (!(node instanceof HTMLElement)) { continue; }

      if (node.matches(childSelector)) {
        return node;
      }

      let selected = (node.shadowRoot || node).querySelector(childSelector);
      if (selected) {
        return selected;
      }
    }
    return null;
  };
};


window.makeSlotSelectAll = (panel) => {
  return (slotSelector, selector) => {
    let slots = panel.shadowRoot.querySelectorAll('slot' + slotSelector);
    let nodes = [];
    for (slot of slots) {
      nodes = nodes.concat(slot.assignedNodes({flatten: true}));
    }

    if (!selector) {
      return nodes;
    }

    let selecteds = [];
    for (node of nodes) {
      if (!(node instanceof HTMLElement)) { continue; }

      if (node.matches && node.matches(selector)) {
        selecteds.push(node);
      }

      for (child of (node.shadowRoot || node).querySelectorAll(selector)) {
        selecteds.push(child);
      }
    }

    return selecteds;
  };
};

