'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  availablePrimaryLabels,
  findMatchingEntry,
  parseMenuEntry,
  selectProviderOption,
  selectionVerified,
} = require('../src/model-selection.cjs');

function fixture(text, attributes = {}) {
  return parseMenuEntry({
    text,
    ariaChecked: attributes.ariaChecked,
    dataState: attributes.dataState,
    badgeText: attributes.badgeText,
  });
}

test('matches ChatGPT reasoning by primary label and ignores secondary version text', () => {
  const entries = [
    fixture('即時\n5.5'),
    fixture('中'),
    fixture('高'),
  ];

  assert.equal(findMatchingEntry(entries, ['instant', '即時']).primaryLabel, '即時');
  assert.equal(findMatchingEntry(entries, ['medium', '中', '中等']).primaryLabel, '中');
  assert.equal(findMatchingEntry(entries, ['high', '高']).primaryLabel, '高');
  assert.equal(findMatchingEntry(entries, ['5.5']), undefined);
});

test('matches English ChatGPT reasoning labels', () => {
  const entries = [
    fixture('Instant\n5.5'),
    fixture('Medium'),
    fixture('High'),
  ];

  assert.equal(findMatchingEntry(entries, ['instant', '即時']).primaryLabel, 'Instant');
  assert.equal(findMatchingEntry(entries, ['medium', '中', '中等']).primaryLabel, 'Medium');
  assert.equal(findMatchingEntry(entries, ['high', '高']).primaryLabel, 'High');
});

test('matches Gemini modes exactly without subtitles or badges', () => {
  const entries = [
    fixture('3.5 Flash-Lite\n回覆最快\n新模型', { badgeText: '新模型' }),
    fixture('3.6 Flash\n全方位協助\n新模型', { badgeText: '新模型' }),
    fixture('3.1 Pro\n進階數學與程式設計'),
    fixture('延伸思考\n解決複雜問題'),
  ];

  assert.equal(findMatchingEntry(entries, ['3.5 Flash-Lite']).primaryLabel, '3.5 Flash-Lite');
  assert.equal(findMatchingEntry(entries, ['3.6 Flash']).primaryLabel, '3.6 Flash');
  assert.equal(findMatchingEntry(entries, ['3.1 Pro']).primaryLabel, '3.1 Pro');
  assert.equal(findMatchingEntry(entries, ['extended thinking', '延伸思考']).primaryLabel, '延伸思考');
  assert.equal(findMatchingEntry(entries, ['3.5 Flash']), undefined);
  assert.deepEqual(availablePrimaryLabels(entries), [
    '3.5 Flash-Lite',
    '3.6 Flash',
    '3.1 Pro',
    '延伸思考',
  ]);
});

test('separates selected-state text from the Gemini primary label', () => {
  const selected = fixture('已選取\n3.1 Pro\n進階數學與程式設計');
  const selectedEnglish = fixture('Selected: Extended Thinking\nSolve complex problems');

  assert.equal(selected.primaryLabel, '3.1 Pro');
  assert.equal(selected.selected, true);
  assert.equal(selectedEnglish.primaryLabel, 'Extended Thinking');
  assert.equal(selectedEnglish.selected, true);
});

test('matches English Gemini Extended Thinking label', () => {
  const entries = [
    fixture('3.1 Pro\nAdvanced math and coding'),
    fixture('Extended Thinking\nSolve complex problems'),
  ];

  assert.equal(
    findMatchingEntry(entries, ['extended thinking', '延伸思考']).primaryLabel,
    'Extended Thinking',
  );
});

test('verifies selection through checked state or the picker primary label', () => {
  const checked = fixture('高', { ariaChecked: 'true' });
  const unchecked = fixture('高', { ariaChecked: 'false' });

  assert.equal(selectionVerified(checked, '', ['high', '高']), true);
  assert.equal(selectionVerified(unchecked, '高', ['high', '高']), true);
  assert.equal(selectionVerified(unchecked, '中', ['high', '高']), false);
  assert.equal(selectionVerified(undefined, 'Pro 延伸', ['Pro Extended', 'Pro 延伸']), true);
});

test('revisits ChatGPT nested menus when verifying a selected model', async () => {
  const previousDocument = global.document;
  const previousKeyboardEvent = global.KeyboardEvent;
  const previousMouseEvent = global.MouseEvent;
  const previousPointerEvent = global.PointerEvent;
  const pointerEventTypes = [];
  let menuState = 'closed';

  function element(text, attributes = {}, click = () => {}) {
    return {
      innerText: text,
      textContent: text,
      click,
      dispatchEvent() {},
      getAttribute(name) {
        const value = typeof attributes[name] === 'function'
          ? attributes[name]()
          : attributes[name];
        return value === undefined ? null : value;
      },
      getClientRects() {
        return [{}];
      },
      querySelector() {
        return null;
      },
    };
  }

  const picker = element('ChatGPT', {}, () => {
    menuState = menuState === 'closed' ? 'top' : 'closed';
  });
  const submenu = element('更多模型', { 'aria-haspopup': 'menu' }, () => {
    menuState = 'nested';
  });
  const model = element(
    'GPT-5.6 Sol\n適合程式設計',
    {
      'aria-checked': () => (menuState === 'nested' ? 'true' : 'false'),
    },
    () => {
      menuState = 'closed';
    },
  );

  global.KeyboardEvent = class KeyboardEvent {};
  global.MouseEvent = class MouseEvent {};
  global.PointerEvent = class PointerEvent {
    constructor(type) {
      pointerEventTypes.push(type);
    }
  };
  global.document = {
    dispatchEvent() {},
    querySelector(selector) {
      return selector === 'button.__composer-pill' ? picker : null;
    },
    querySelectorAll(selector) {
      if (selector === 'button') return [picker];
      if (menuState === 'top') return [submenu];
      if (menuState === 'nested') return [model];
      return [];
    },
  };

  try {
    const result = await selectProviderOption({
      provider: 'chatgpt',
      targetAliases: ['GPT-5.6 Sol'],
      verificationAliases: ['GPT-5.6 Sol'],
      sleep: async () => {},
    });

    assert.equal(result.ok, true);
    assert.equal(result.selected, 'GPT-5.6 Sol');
    assert.deepEqual(pointerEventTypes, [
      'pointerdown',
      'pointerup',
      'pointerenter',
      'pointermove',
      'pointerdown',
      'pointerup',
      'pointerenter',
      'pointermove',
    ]);
  } finally {
    global.document = previousDocument;
    global.KeyboardEvent = previousKeyboardEvent;
    global.MouseEvent = previousMouseEvent;
    global.PointerEvent = previousPointerEvent;
  }
});

// The failure nothing else here guards: the option is found and clicked, and the
// page then does nothing -- the entry never becomes checked and the picker keeps
// naming the old model. That is what a provider-side UI change looks like from
// here, and it needs no code deletion to happen.
//
// `switch_semantic_option` in src/main.rs treats `result.ok` as ground truth, so
// reporting success on an unverified selection makes ask-bridge print that the
// model was switched, type the prompt anyway, and exit 0 with an answer from
// whatever model was already selected. The `selectionVerified` unit test above
// cannot see it: it never runs the two-pass reopen-and-recheck flow that decides
// `verified`. The `ok: true` half of the contract is the ChatGPT test above,
// which walks the same reopen and does verify -- so this pair cannot be
// satisfied by a picker that simply refuses everything.
test('a selection that never verifies is reported as a failure', async () => {
  const previousDocument = global.document;
  const previousKeyboardEvent = global.KeyboardEvent;
  const previousMouseEvent = global.MouseEvent;
  const previousPointerEvent = global.PointerEvent;

  function element(text, attributes = {}, click = () => {}) {
    return {
      innerText: text,
      textContent: text,
      click,
      dispatchEvent() {},
      getAttribute(name) {
        const value = attributes[name];
        return value === undefined ? null : value;
      },
      getClientRects() {
        return [{}];
      },
      querySelector() {
        return null;
      },
    };
  }

  let pickerClicks = 0;
  const picker = element('Model picker', { 'aria-label': 'Model picker' }, () => {
    pickerClicks += 1;
  });
  let optionClicks = 0;
  // aria-checked stays 'false' however often it is clicked, and the picker keeps
  // its own label, so neither route to `selectionVerified` can ever succeed.
  const option = element(
    '3.1 Pro\nAdvanced math and coding',
    { 'aria-checked': 'false' },
    () => {
      optionClicks += 1;
    },
  );

  global.KeyboardEvent = class KeyboardEvent {};
  global.MouseEvent = class MouseEvent {};
  global.PointerEvent = class PointerEvent {};
  global.document = {
    dispatchEvent() {},
    querySelector() {
      return null;
    },
    querySelectorAll(selector) {
      if (selector === 'button') return [picker];
      if (selector.includes('menuitem')) return [option];
      return [];
    },
  };

  try {
    const result = await selectProviderOption({
      provider: 'gemini',
      targetAliases: ['3.1 Pro'],
      verificationAliases: ['3.1 Pro'],
      sleep: async () => {},
    });

    assert.equal(result.ok, false, 'an unverified selection must not be reported as done');
    assert.match(result.error, /could not be verified for 3\.1 Pro/);
    // Anti-tautology: this has to be a *verification* failure. The
    // option-not-found path returns `ok: false` too, for a different reason, and
    // would leave the verification branch untested.
    assert.equal(optionClicks, 1, 'the option itself must have been clicked');
    assert.equal(pickerClicks, 2, 'the picker must have been reopened to re-check');
    assert.deepEqual(result.available, ['3.1 Pro']);
  } finally {
    global.document = previousDocument;
    global.KeyboardEvent = previousKeyboardEvent;
    global.MouseEvent = previousMouseEvent;
    global.PointerEvent = previousPointerEvent;
  }
});
