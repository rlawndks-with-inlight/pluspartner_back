const express = require('express');
const router = express.Router();
const {
    onSignUp, onLoginById, onLogout, getUserToken, getUsers
} = require('./api')

router.post('/adduser', onSignUp);
router.post('/loginbyid', onLoginById);
router.post('/logout', onLogout);
router.get('/auth', getUserToken);
router.get('/users', getUsers);

module.exports = router;