const express = require('express');
const router = express.Router();
const { upload } = require('../config/multerConfig')
const {
    onSignUp, onLoginById, onLogout, getUserToken, getUsers, addMaster
} = require('./api')

router.post('/adduser', onSignUp);
router.post('/addmaster', upload.single('master'), addMaster);
router.post('/loginbyid', onLoginById);
router.post('/logout', onLogout);
router.get('/auth', getUserToken);
router.get('/users', getUsers);

module.exports = router;