//this should be removed
const express = require('express');
const router = express.Router();

router.get('/private', (req, res, next) => {
  if (req.isAuthenticated()) {
    res.render('passport/private');
  } else {
    res.render('error', { errorMessage: 'This is a protected route' });
  }
});

module.exports = router;
