'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
 const nodes = [], timers = [], notifications = [], pending = [];
 let failStart = true, inFlight = 0, maximumInFlight = 0;
 const context = vm.createContext({
  rpc: { declare: () => () => {} }, view: { extend: v => v },
  _: value => value,
  E: (tag, attrs, children) => {
   const node = { tag, attrs, children, style: {}, disabled: false, events: {},
    addEventListener(event, fn) { this.events[event] = fn; } };
   nodes.push(node); return node;
  },
  dom: { content: (node, children) => { node.children = children; } },
  ui: { addNotification: (_, body, type) => notifications.push(type) },
  window: {
   setTimeout: fn => { timers.push(fn); return timers.length; },
   setInterval: fn => { timers.push(fn); return timers.length; },
   clearInterval: () => {}
  },
  fetch: () => Promise.resolve({ json: () => Promise.resolve({ tag_name: 'v0.7.0', html_url: 'release' }) }),
  fs: { exec: (path, args) => {
   if (args[0] === 'start') {
    if (failStart) { failStart = false; return Promise.reject(new Error('RPC fixture')); }
    return Promise.resolve({ stdout: '{"started":true}' });
   }
   assert.equal(args[0], 'status');
   inFlight++; maximumInFlight = Math.max(maximumInFlight, inFlight);
   return new Promise(resolve => pending.push(value => { inFlight--; resolve(value); }));
  } }
 });
 vm.runInContext('String.prototype.format=function(){var a=arguments,i=0;return this.replace(/%s/g,function(){return a[i++];});};', context);
 const source = fs.readFileSync('luci-app-fnport/htdocs/luci-static/resources/view/fnport/status.js', 'utf8');
 const page = vm.runInContext('(function(){' + source + '\n})()', context);
 const flush = () => new Promise(resolve => setImmediate(resolve));
 page.renderUpdate({ now: { version: '0.6.1-r1' } });
 await flush();
 const button = nodes.find(n => n.tag === 'button');
 assert.ok(button);
 button.events.click(); await flush();
 assert.deepEqual(notifications, ['danger']);
 assert.equal(button.disabled, false, 'start failure must allow retry');

 button.events.click(); await flush();
 button.events.click(); await flush();
 assert.equal(pending.length, 1, 'repeated click must not launch another updater');
 assert.equal(timers.length, 0, 'a slow RPC must not start overlapping polls');
 pending.shift()({ stdout: JSON.stringify({ running: true, log: 'Downloading package' }) });
 await flush();
 assert.equal(timers.length, 1);
 timers.shift()(); await flush();
 assert.equal(maximumInFlight, 1);
 pending.shift()({ stdout: JSON.stringify({ running: false, log: 'Download failed\nexit 4\n' }) });
 await flush();
 assert.deepEqual(notifications, ['danger', 'danger']);
 assert.equal(timers.length, 0);
 assert.equal(button.disabled, false);

 button.events.click(); await flush();
 pending.shift()({ stdout: JSON.stringify({ running: false, log: 'Done\nexit 0\n' }) });
 await flush();
 assert.deepEqual(notifications, ['danger', 'danger', 'info']);
 assert.equal(maximumInFlight, 1);
 assert.equal(button.disabled, false);
 console.log('LuCI update: one RPC at a time, one notification per attempt, retry after failure: passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
