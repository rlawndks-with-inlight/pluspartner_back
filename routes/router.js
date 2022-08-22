const express = require('express');
const router = express.Router();
const { upload } = require('../config/multerConfig')
const {
    onLoginById, getUserToken, onLogout,//auth
    getUsers, getOneWord, getOneEvent, getItems, getItem, getHomeContent,//select
    addMaster, onSignUp, addOneWord, addOneEvent, addItem, addIssueCategory,//insert 
    updateUser, updateItem, updateIssueCategory,//update
    deleteItem
} = require('./api')

router.post('/adduser', onSignUp);
router.post('/addmaster', upload.single('master'), addMaster);
router.post('/loginbyid', onLoginById);
router.post('/logout', onLogout);
router.get('/auth', getUserToken);
router.get('/users', getUsers);
router.post('/addoneword', upload.single('content'), addOneWord);
router.post('/addoneevent', upload.single('content'), addOneEvent);
router.post('/additem', upload.single('content'), addItem);
router.post('/updateitem', upload.single('content'), updateItem);
router.post('/addissuecategory', addIssueCategory);
router.post('/updateissuecategory', updateIssueCategory);

router.post('/deleteitem', deleteItem);
router.post('/updateuser', updateUser);
router.get('/oneword', getOneWord);
router.get('/oneevent', getOneEvent);
router.get('/items', getItems);
router.get('/item', getItem);
router.get('/gethomecontent', getHomeContent);

module.exports = router;