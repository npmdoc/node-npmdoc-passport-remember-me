# api documentation for  [passport-remember-me (v0.0.1)](https://github.com/jaredhanson/passport-remember-me#readme)  [![npm package](https://img.shields.io/npm/v/npmdoc-passport-remember-me.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-passport-remember-me) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-passport-remember-me.svg)](https://travis-ci.org/npmdoc/node-npmdoc-passport-remember-me)
#### Remember Me cookie authentication strategy for Passport.

[![NPM](https://nodei.co/npm/passport-remember-me.png?downloads=true)](https://www.npmjs.com/package/passport-remember-me)

[![apidoc](https://npmdoc.github.io/node-npmdoc-passport-remember-me/build/screenCapture.buildNpmdoc.browser.%2Fhome%2Ftravis%2Fbuild%2Fnpmdoc%2Fnode-npmdoc-passport-remember-me%2Ftmp%2Fbuild%2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-passport-remember-me/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-passport-remember-me/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-passport-remember-me/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Jared Hanson",
        "email": "jaredhanson@gmail.com",
        "url": "http://www.jaredhanson.net/"
    },
    "bugs": {
        "url": "http://github.com/jaredhanson/passport-remember-me/issues"
    },
    "dependencies": {
        "passport": "~0.1.1",
        "pkginfo": "0.2.x"
    },
    "description": "Remember Me cookie authentication strategy for Passport.",
    "devDependencies": {
        "chai": "1.x.x",
        "mocha": "1.x.x"
    },
    "directories": {},
    "dist": {
        "shasum": "0aa6095c82480f44619456aef363ccb929bc2bc3",
        "tarball": "https://registry.npmjs.org/passport-remember-me/-/passport-remember-me-0.0.1.tgz"
    },
    "engines": {
        "node": ">= 0.4.0"
    },
    "homepage": "https://github.com/jaredhanson/passport-remember-me#readme",
    "keywords": [
        "passport",
        "cookie",
        "persistent",
        "rememberme",
        "auth",
        "authn",
        "authentication"
    ],
    "licenses": [
        {
            "type": "MIT",
            "url": "http://www.opensource.org/licenses/MIT"
        }
    ],
    "main": "./lib",
    "maintainers": [
        {
            "name": "jaredhanson",
            "email": "jaredhanson@gmail.com"
        }
    ],
    "name": "passport-remember-me",
    "optionalDependencies": {},
    "readme": "# Passport-Remember Me\n\n[Passport](http://passportjs.org/) strategy for authenticating based on a\nremember me cookie.\n\nThis module lets you authenticate using a remember me cookie (aka persistent\nlogin) in your Node.js applications.  By plugging into Passport, remember me\nauthentication can be easily and unobtrusively integrated into any application\nor framework that supports [Connect](http://www.senchalabs.org/connect/)-style\nmiddleware, including [Express](http://expressjs.com/).\n\n## Install\n\n    $ npm install passport-remember-me\n\n## Usage\n\n#### Configure Strategy\n\nThe remember me authentication strategy authenticates users using a token stored\nin a remember me cookie.  The strategy requires a 'verify' callback, which\nconsumes the token and calls 'done' providing a user.\n\nThe strategy also requires an 'issue' callback, which issues a new token.  For\nsecurity reasons, remember me tokens should be invalidated after being used.\nThe 'issue' callback supplies a new token that will be stored in the cookie for\nnext use.\n\n    passport.use(new RememberMeStrategy(\n      function(token, done) {\n        Token.consume(token, function (err, user) {\n          if (err) { return done(err); }\n          if (!user) { return done(null, false); }\n          return done(null, user);\n        });\n      },\n      function(user, done) {\n        var token = utils.generateToken(64);\n        Token.save(token, { userId: user.id }, function(err) {\n          if (err) { return done(err); }\n          return done(null, token);\n        });\n      }\n    ));\n\n#### Authenticate Requests\n\nUse 'passport.authenticate()', specifying the ''remember-me'' strategy, to\nauthenticate requests.\n\nThis is typically used in an application's middleware stack, to log the user\nback in the next time they visit any page on your site.  For example:\n\n    app.configure(function() {\n      app.use(express.cookieParser());\n      app.use(express.bodyParser());\n      app.use(express.session({ secret: 'keyboard cat' }));\n      app.use(passport.initialize());\n      app.use(passport.session());\n      app.use(passport.authenticate('remember-me'));\n      app.use(app.router);\n    });\n    \nNote that 'passport.session()' should be mounted *above* 'remember-me'\nauthentication, so that tokens aren't exchanged for currently active login\nsessions.\n\n#### Setting the Remember Me Cookie\n\nIf the user enables \"remember me\" mode, an initial cookie should be set when\nthey login.\n\n    app.post('/login', \n      passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),\n      function(req, res, next) {\n        // issue a remember me cookie if the option was checked\n        if (!req.body.remember_me) { return next(); }\n    \n        var token = utils.generateToken(64);\n        Token.save(token, { userId: req.user.id }, function(err) {\n          if (err) { return done(err); }\n          res.cookie('remember_me', token, { path: '/', httpOnly: true, maxAge: 604800000 }); // 7 days\n          return next();\n        });\n      },\n      function(req, res) {\n        res.redirect('/');\n      });\n\n## Examples\n\nFor a complete, working example, refer to the [login example](https://github.com/jaredhanson/passport-remember-me/tree/master/examples/login).\n\n## Tests\n\n    $ npm install\n    $ make test\n\n[![Build Status](https://secure.travis-ci.org/jaredhanson/passport-remember-me.png)](http://travis-ci.org/jaredhanson/passport-remember-me)\n\n## Credits\n\n  - [Jared Hanson](http://github.com/jaredhanson)\n\n## License\n\n[The MIT License](http://opensource.org/licenses/MIT)\n\nCopyright (c) 2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>\n",
    "repository": {
        "type": "git",
        "url": "git://github.com/jaredhanson/passport-remember-me.git"
    },
    "scripts": {
        "test": "NODE_PATH=./lib node_modules/.bin/mocha --reporter spec --require test/bootstrap/node test/*.test.js"
    },
    "version": "0.0.1"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module passport-remember-me](#apidoc.module.passport-remember-me)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy (options, verify, issue)](#apidoc.element.passport-remember-me.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy.super_ ()](#apidoc.element.passport-remember-me.Strategy.super_)
1.  object <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy.prototype
1.  object <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy.super_.prototype
1.  object <span class="apidocSignatureSpan">passport-remember-me.</span>utils
1.  string <span class="apidocSignatureSpan">passport-remember-me.</span>version

#### [module passport-remember-me.Strategy](#apidoc.module.passport-remember-me.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy (options, verify, issue)](#apidoc.element.passport-remember-me.Strategy.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.Strategy.</span>super_ ()](#apidoc.element.passport-remember-me.Strategy.super_)

#### [module passport-remember-me.Strategy.prototype](#apidoc.module.passport-remember-me.Strategy.prototype)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.Strategy.prototype.</span>authenticate (req, options)](#apidoc.element.passport-remember-me.Strategy.prototype.authenticate)

#### [module passport-remember-me.Strategy.super_](#apidoc.module.passport-remember-me.Strategy.super_)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.Strategy.</span>super_ ()](#apidoc.element.passport-remember-me.Strategy.super_.super_)

#### [module passport-remember-me.Strategy.super_.prototype](#apidoc.module.passport-remember-me.Strategy.super_.prototype)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.Strategy.super_.prototype.</span>authenticate (req, options)](#apidoc.element.passport-remember-me.Strategy.super_.prototype.authenticate)

#### [module passport-remember-me.utils](#apidoc.module.passport-remember-me.utils)
1.  [function <span class="apidocSignatureSpan">passport-remember-me.utils.</span>merge (a, b)](#apidoc.element.passport-remember-me.utils.merge)



# <a name="apidoc.module.passport-remember-me"></a>[module passport-remember-me](#apidoc.module.passport-remember-me)

#### <a name="apidoc.element.passport-remember-me.Strategy"></a>[function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy (options, verify, issue)](#apidoc.element.passport-remember-me.Strategy)
- description and source-code
```javascript
function Strategy(options, verify, issue) {
  if (typeof options == 'function') {
    issue = verify;
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('remember me cookie authentication strategy requires a verify function');
  if (!issue) throw new Error('remember me cookie authentication strategy requires an issue function');

  var opts = { path: '/', httpOnly: true, maxAge: 604800000 }; // maxAge: 7 days
  this._key = options.key || 'remember_me';
  this._opts = utils.merge(opts, options.cookie);

  passport.Strategy.call(this);
  this.name = 'remember-me';
  this._verify = verify;
  this._issue = issue;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-remember-me.Strategy.super_"></a>[function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy.super_ ()](#apidoc.element.passport-remember-me.Strategy.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-remember-me.Strategy"></a>[module passport-remember-me.Strategy](#apidoc.module.passport-remember-me.Strategy)

#### <a name="apidoc.element.passport-remember-me.Strategy.Strategy"></a>[function <span class="apidocSignatureSpan">passport-remember-me.</span>Strategy (options, verify, issue)](#apidoc.element.passport-remember-me.Strategy.Strategy)
- description and source-code
```javascript
function Strategy(options, verify, issue) {
  if (typeof options == 'function') {
    issue = verify;
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('remember me cookie authentication strategy requires a verify function');
  if (!issue) throw new Error('remember me cookie authentication strategy requires an issue function');

  var opts = { path: '/', httpOnly: true, maxAge: 604800000 }; // maxAge: 7 days
  this._key = options.key || 'remember_me';
  this._opts = utils.merge(opts, options.cookie);

  passport.Strategy.call(this);
  this.name = 'remember-me';
  this._verify = verify;
  this._issue = issue;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-remember-me.Strategy.super_"></a>[function <span class="apidocSignatureSpan">passport-remember-me.Strategy.</span>super_ ()](#apidoc.element.passport-remember-me.Strategy.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-remember-me.Strategy.prototype"></a>[module passport-remember-me.Strategy.prototype](#apidoc.module.passport-remember-me.Strategy.prototype)

#### <a name="apidoc.element.passport-remember-me.Strategy.prototype.authenticate"></a>[function <span class="apidocSignatureSpan">passport-remember-me.Strategy.prototype.</span>authenticate (req, options)](#apidoc.element.passport-remember-me.Strategy.prototype.authenticate)
- description and source-code
```javascript
authenticate = function (req, options) {
  // The rememeber me cookie is only consumed if the request is not
  // authenticated.  This is in preference to the session, which is typically
  // established at the same time the remember me cookie is issued.
  if (req.isAuthenticated()) { return this.pass(); }

  var token = req.cookies[this._key];

  // Since the remember me cookie is primarily a convenience, the lack of one is
  // not a failure.  In this case, a response should be rendered indicating a
  // logged out state, rather than denying the request.
  if (!token) { return this.pass(); }

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }

    // Express exposes the response to the request.  We need the response to set
    // a cookie, so we'll grab it this way.  This breaks the encapsulation of
    // Passport's Strategy API, but is acceptable for this strategy.
    var res = req.res;

    if (!user) {
      // The remember me cookie was not valid.  However, because this
      // authentication method is primarily a convenience, we don't want to
      // deny the request.  Instead we'll clear the invalid cookie and proceed
      // to respond in a manner which indicates a logged out state.
      //
      // Note that a failure at this point may indicate a possible theft of the
      // cookie.  If handling this situation is a requirement, it is up to the
      // application to encode the value in such a way that this can be detected.
      // For a discussion on such matters, refer to:
      //   http://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice/
      //   http://jaspan.com/improved_persistent_login_cookie_best_practice
      //   http://web.archive.org/web/20130214051957/http://jaspan.com/improved_persistent_login_cookie_best_practice
      //   http://stackoverflow.com/questions/549/the-definitive-guide-to-forms-based-website-authentication

      res.clearCookie(self._key);
      return self.pass();
    }

    // The remember me cookie was valid and consumed.  For security reasons,
    // the just-used token should have been invalidated by the application.
    // A new token will be issued and set as the value of the remember me
    // cookie.
    function issued(err, val) {
      if (err) { return self.error(err); }
      res.cookie(self._key, val, self._opts);
      return self.success(user, info);
    }

    self._issue(user, issued);
  }

  self._verify(token, verified);
}
```
- example usage
```shell
...
      return done(null, token);
    });
  }
));

#### Authenticate Requests

Use 'passport.authenticate()', specifying the ''remember-me'' strategy, to
authenticate requests.

This is typically used in an application's middleware stack, to log the user
back in the next time they visit any page on your site.  For example:

app.configure(function() {
  app.use(express.cookieParser());
...
```



# <a name="apidoc.module.passport-remember-me.Strategy.super_"></a>[module passport-remember-me.Strategy.super_](#apidoc.module.passport-remember-me.Strategy.super_)

#### <a name="apidoc.element.passport-remember-me.Strategy.super_.super_"></a>[function <span class="apidocSignatureSpan">passport-remember-me.Strategy.</span>super_ ()](#apidoc.element.passport-remember-me.Strategy.super_.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-remember-me.Strategy.super_.prototype"></a>[module passport-remember-me.Strategy.super_.prototype](#apidoc.module.passport-remember-me.Strategy.super_.prototype)

#### <a name="apidoc.element.passport-remember-me.Strategy.super_.prototype.authenticate"></a>[function <span class="apidocSignatureSpan">passport-remember-me.Strategy.super_.prototype.</span>authenticate (req, options)](#apidoc.element.passport-remember-me.Strategy.super_.prototype.authenticate)
- description and source-code
```javascript
authenticate = function (req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
}
```
- example usage
```shell
...
      return done(null, token);
    });
  }
));

#### Authenticate Requests

Use 'passport.authenticate()', specifying the ''remember-me'' strategy, to
authenticate requests.

This is typically used in an application's middleware stack, to log the user
back in the next time they visit any page on your site.  For example:

app.configure(function() {
  app.use(express.cookieParser());
...
```



# <a name="apidoc.module.passport-remember-me.utils"></a>[module passport-remember-me.utils](#apidoc.module.passport-remember-me.utils)

#### <a name="apidoc.element.passport-remember-me.utils.merge"></a>[function <span class="apidocSignatureSpan">passport-remember-me.utils.</span>merge (a, b)](#apidoc.element.passport-remember-me.utils.merge)
- description and source-code
```javascript
merge = function (a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
}
```
- example usage
```shell
...

/**
* Merge object b with object a.
*
*     var a = { foo: 'bar' }
*       , b = { bar: 'baz' };
*
*     utils.merge(a, b);
*     // => { foo: 'bar', bar: 'baz' }
*
* @param {Object} a
* @param {Object} b
* @return {Object}
* @api private
*/
...
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
