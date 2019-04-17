const express        = require("express");
const passportRouter = express.Router();
const bcrypt         = require('bcrypt');
const User           = require('../models/user');
const router         = express.Router();
const passport       = require('passport');
const zxcvbn         = require('zxcvbn');
const ensureLogin    = require("connect-ensure-login");


router.get('/private', (req, res, next) => {
  if (req.isAuthenticated()) {
    res.render('passport/private');
  }else{
    res.render('error', { errorMessage: 'This is a protected route' });
  }
});


router.get('/logout', (req, res, next) => {
  req.logout();
  res.redirect('/');
});

router.get('/login', (req, res, next) => {
  res.render('passport/login', {
    errorMessage: req.flash('error')
  });
});

router.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/passport/private',
    failureRedirect: '/passport/login',
    failureFlash: true,
    passReqToCallback: true
  })
);

router.get('/signup', (req, res, next) => {
  res.render('passport/signup', {
    errorMessage: req.flash('error')
  });
});

router.post('/signup', (req, res, next) => {
  const username     = req.body.username;
  const password     = req.body.password;
  const salt         = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  if (username === '' || password === '') {
    res.render('passport/signup', {
      errorMessage: 'You need a username and a password to signup'
    });
    return;
  }
  const passwordStrength = zxcvbn(password);
  if (password.length < 6) {
    res.render('passport/signup', {
      errorMessage: 'Your password needs 6 or more characters'
    });
    return;
  }
  if (passwordStrength.score === 0) {
    res.render('passport/signup', {
      errorMessage: passwordStrength.feedback.warning
    });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render('passport/signup', {
          errorMessage: 'There is already a signuped user with this username'
        });
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect('/');
        })
        .catch(err => {
          console.error('Error while signuping new user', err);
          next();
        });
    })
    .catch(err => {
      console.error('Error while looking for user', err);
  });
});

module.exports = router;
