'use strict';
var test = require('tape');
var Auth = require('../');

var auth = Auth();
test('auth.*() methods return middlewares(functions)', function (t) {
  var noop = function () {};
  t.equal('function', typeof auth(noop));
  t.equal('function', typeof auth.nopreauth(noop));
  t.equal('function', typeof auth.pass());
  t.equal('function', typeof auth.client());
  t.equal('function', typeof auth.user());
  t.equal('function', typeof auth.scope());
  t.equal('function', typeof auth.owner());
  t.end();
});

test('auth.pass() always pass request', function (t) {
  var req = {};
  t.plan(1);
  auth.pass()(req, {}, function () {
    t.ok(req.authPass);
  });
});

test('auth.client() will pass request with req.authInfo.client provided', function (t) {
  var req1 = {}, req2 = {authInfo: {client: {name: 'testclient'}}};
  t.plan(2);
  auth.client()(req1, {}, function () {
    t.notOk(req1.authPass);
  });
  auth.client()(req2, {}, function () {
    t.ok(req2.authPass);
  });
});

test('auth.user() will pass request with req.user provided', function (t) {
  var req1 = {};
  var req2 = {user: {}};
  var req3 = {user: null};
  var req4 = {user: {name: 'testuser'}};
  t.plan(4);
  auth.user()(req1, {}, function () {
    t.notOk(req1.authPass);
  });
  auth.user()(req2, {}, function () {
    t.notOk(req2.authPass);
  });
  auth.user()(req3, {}, function () {
    t.notOk(req3.authPass);
  });
  auth.user()(req4, {}, function () {
    t.ok(req4.authPass);
  });
});

test('auth.scope() will pass request when request has some scope', function (t) {
  var req;
  t.plan(4);
  auth.scope('c', 'd')(req = {user: {name: 'testuser'}}, {}, function () {
    t.notOk(req.authPass);
  });
  auth.scope('c', 'd')(req = {user: {name: 'testuser'}, authInfo: {scope: ['a']}}, {}, function () {
    t.notOk(req.authPass);
  });
  auth.scope('a', 'b')(req = {user: {name: 'testuser'}, authInfo: {scope: ['a']}}, {}, function () {
    t.ok(req.authPass);
  });
  auth.scope('b', 'c')(req = {user: {name: 'testuser'}, authInfo: {scope: ['a', 'b']}}, {}, function () {
    t.ok(req.authPass);
  });
});

test('auth.owner() only pass request when it request for it\'s own resource', function (t) {
  var req;
  t.plan(2);
  auth.owner()(req = {user: {id: '123'}, params: {userId: '123'}}, {}, function () {
    t.ok(req.authPass);
  });
  auth.owner()(req = {user: {id: '123'}, params: {userId: '456'}}, {}, function () {
    t.notOk(req.authPass);
  });
});

test('preauth middleware', function (t) {
  var auth = Auth(function (req, res, next) {
    req.user = req.query.user ? {user: 'testuser'} : null;
    req.authInfo = req.query.scope ? {scope: ['a']} : null;
    next();
  });
  var req;
  t.plan(7);
  auth.user()(req = {query:{}}, {}, function () {
    t.notOk(req.authPass);
  });
  auth.user()(req = {query:{user:true}}, {}, function () {
    t.ok(req.authPass);
  });
  auth.scope('a')(req = {query:{}}, {}, function () {
    t.notOk(req.authPass);
  });
  auth.scope('a')(req = {query:{user: true}}, {}, function () {
    t.notOk(req.authPass);
  });
  auth.scope('a')(req = {query:{scope: true}}, {}, function () {
    t.ok(req.authPass);
  });
  auth.scope('a')(req = {query:{user: true, scope: true}}, {}, function () {
    t.ok(req.authPass);
  });
  auth.scope('b')(req = {query:{user: true, scope: true}}, {}, function () {
    t.notOk(req.authPass);
  });
});

test('custom auth logic', function (t) {
  t.plan(4);
  var auth = Auth(function (req, res, next) {
    req.user = req.query.user ? {user: 'testuser'} : null;
    req.authInfo = req.query.scope ? {scope: ['a']} : null;
    next();
  });
  var req;
  var custom = function (req) {
    return req.query.hello === 'world';
  };
  auth(custom)(req = {query:{user: true, hello: 'world'}}, {}, function () {
    t.ok('authInfo' in req);
    t.ok(req.authPass);
  });
  auth.nopreauth(custom)(req = {query:{hello: 'world'}}, {}, function () {
    t.notOk('authInfo' in req);
    t.ok(req.authPass);
  });
});
