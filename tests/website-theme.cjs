// Run with: node tests/website-theme.cjs
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

const html = readFileSync(join(__dirname, '../website/src/index.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]);
scripts.forEach(script => new vm.Script(script)); // Check every inline page script.
const script = scripts.find(script => script.includes('/* THEME PREFERENCE'));
const preference = script.slice(script.indexOf('/* THEME PREFERENCE'), script.indexOf('/* GITHUB STATS'));
const toggle = script.slice(script.indexOf('/* THEME TOGGLE */'));

function page(hour, stored = 'dark', storageBlocked = false) {
  const events = {};
  const dataset = {};
  const icon = {};
  const state = { hour, stored, svg: null };
  vm.runInNewContext(preference + toggle, {
    Date: class { getHours() { return state.hour; } },
    localStorage: {
      removeItem(key) {
        if (storageBlocked) throw new Error('Storage blocked');
        assert.equal(key, 'theme');
        state.stored = null;
      },
      getItem() { return state.stored; },
      setItem() { assert.fail('Theme must not be persisted'); },
    },
    document: {
      documentElement: { dataset },
      getElementById: id => id === 'theme-icon' ? icon : {
        addEventListener: (name, callback) => { events[name] = callback; },
      },
      addEventListener: (name, callback) => { events[name] = callback; },
    },
    window: {
      _svgToLight() { state.svg = 'light'; },
      _svgToDark() { state.svg = 'dark'; },
    },
    setInterval(callback, delay) {
      assert.equal(delay, 60000);
      events.tick = callback;
    },
  });
  state.events = events;
  state.check = expected => {
    assert.equal(dataset.theme || 'dark', expected);
    assert.equal(state.svg, expected);
    assert.equal(icon.textContent, expected === 'light' ? '☾' : '☀');
  };
  return state;
}

for (const [hour, expected] of [[0, 'dark'], [6, 'dark'], [7, 'light'], [18, 'light'], [19, 'dark'], [23, 'dark']]) {
  const p = page(hour, expected === 'light' ? 'dark' : 'light');
  p.check(expected);
  assert.equal(p.stored, null);
}
page(12, 'dark', true).check('light');
const p = page(18);
p.events.click();
p.check('dark');
p.events.tick();
p.check('dark'); // A timer tick must not undo a manual choice in the same period.
page(18).check('light'); // Reload returns to automatic mode.
p.hour = 19;
p.events.tick();
p.check('dark');
p.events.click();
p.check('light');
p.events.visibilitychange();
p.check('light');
p.hour = 7;
p.events.visibilitychange();
p.check('light');
p.hour = 19;
p.events.tick();
p.check('dark'); // Automatic updates continue after manual toggles.
console.log('Theme checks passed: old storage, local hours, manual override, reload, timer and visibility.');
