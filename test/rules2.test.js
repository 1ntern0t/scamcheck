'use strict';
// Second-pass rule families. Phrases come from the hand-written tuning set
// (set 2) and generic descriptions of each scam type, not from set 3.
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

const ids = (r) => r.reasons.map((x) => x.id);
const L = ['low', 'medium', 'high', 'critical'];
const atLeast = (r, lvl) => L.indexOf(r.level) >= L.indexOf(lvl);

const FLAG = [
  ['Mom, I broke my phone, this is my new number. Can you pay a bill for me today? I will pay you back.', ['msg.family_emergency', 'msg.money_request']],
  ['Your toll balance is unpaid. Avoid late penalties: https://tolls-pay.example', ['msg.fee_notice', 'combo.notice_with_link']],
  ['Parking notice: unpaid parking fine of $25. Pay at https://city-fines.example/pay', ['msg.fee_notice']],
  ['We tried to deliver your parcel. Reschedule here: https://parcel-reschedule.net/r?id=8812', ['msg.delivery_problem', 'combo.notice_with_link']],
  ['Work from home: reship packages for $500/day. Just send a copy of your ID and SSN to start.', ['msg.job_scam', 'msg.identity_docs']],
  ['Earn $400 per day doing simple product rating tasks, top up your account to unlock commission', ['msg.job_scam']],
  ['Lost crypto? Our recovery experts can retrieve your stolen funds for a small upfront fee.', ['msg.recovery_scam', 'msg.advance_fee']],
  ['This is your bank fraud department. We will send a courier to collect your card, please write your PIN on a paper.', ['msg.bank_impersonation']],
  ['Hi, I accidentally sent you a code by text, could you forward it to me please?', ['msg.code_forward']],
  ['A withdrawal of 2.1 BTC was requested. If this was not you, call +1 (888) 555-0199.', ['msg.callback_number']],
  ['Dear customer, kindly re-enter your card number on our secure portal to continue service', ['msg.card_details']],
  ['WhatsApp me at +44 7700 900123 for your refund from the order you returned', ['msg.refund_offchannel']],
  ['Your mailbox storage is full. Messages will be deleted. Click to expand storage: https://mail-upgrade.example', ['msg.storage_full', 'msg.deletion_threat']],
  ['My uncle showed me a trading platform, I made 40k last month trading. Want me to show you how?', ['msg.investment_pitch']],
  ['Hi dear, I am a soldier on peacekeeping mission. I need help to move my savings', ['msg.romance_funds']],
  ['The Ledger team found a data leak. Please migrate your funds to this safe address now', ['msg.safe_wallet']],
  ['Please install the remote support tool from https://quick-help-desk.example so I can patch your laptop', ['msg.remote_access']],
  ['Exclusive invite: our private investment club pays a fixed 4% every day.', ['msg.guaranteed_returns']],
  ['Your bank card has been locked. Reply with your PIN to unlock it.', ['msg.password_request']]
];
for (const [text, want] of FLAG) {
  test('flags: ' + text.slice(0, 55), () => {
    const r = sc.analyze(text);
    for (const id of want) assert.ok(ids(r).includes(id), id + ' missing: ' + JSON.stringify(ids(r)));
    assert.ok(atLeast(r, 'medium'), 'level ' + r.level + ' score ' + r.score);
  });
}

const QUIET = [
  'Can you pay me back for dinner when you get a chance?',
  'Your package has shipped and will arrive Thursday.',
  'The shared drive is almost full, please clean up old videos.',
  'I lost my phone charger at the office, has anyone seen it?',
  'Shipping fee for the group order was $6, split four ways.',
  'Our job board lists remote roles at https://www.linkedin.com/jobs',
  'Never give anyone the code we text you, not even our staff.',
  'The courier delivered the documents this morning.'
];
for (const text of QUIET) {
  test('stays low: ' + text.slice(0, 55), () => {
    const r = sc.analyze(text);
    assert.equal(r.level, 'low', JSON.stringify(ids(r)) + ' score ' + r.score);
  });
}
