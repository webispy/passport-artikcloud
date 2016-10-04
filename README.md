# passport-artikcloud

[Passport](http://passportjs.org/) strategy for authenticating with [ARTIK Cloud](http://artik.cloud/)
using the OAuth 2.0 API.

## Install

    $ npm install passport-artikcloud

## Usage

#### Configure Strategy

```js
passport.use(new ARTIKCloudStrategy({
    clientID: EXAMPLE_CLIENT_ID,
    clientSecret: EXAMPLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/example/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ exampleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```

#### Authenticate Requests

```js
app.get('/auth/example',
  passport.authenticate('artikcloud'));

app.get('/auth/example/callback',
  passport.authenticate('artikcloud', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2016 Inho Oh <webispy@gmail.com>
