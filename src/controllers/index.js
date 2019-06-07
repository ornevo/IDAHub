var express = require('express');
var router = express.Router();

// import handlers
import NewUser from "./users/new-user"; 


/* GET home page. */
router.get('/', function(req, res, next) {
  res.json({
    "Message": 'welcome!'
  })
});

/* User apis */
router.post("/api/users/new", NewUser.validators, NewUser.handler);

module.exports = router;
