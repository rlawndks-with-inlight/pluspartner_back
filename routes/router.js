const express = require('express');
const router = express.Router();
const { upload } = require('../config/multerConfig')
const {
    onLoginById, getUserToken, onLogout,//auth
    getUsers, getOneWord, getOneEvent, getItems, getItem, getHomeContent, getSetting,//select
    addMaster, onSignUp, addOneWord, addOneEvent, addItem, addIssueCategory, addNoteImage, addVideo, addSetting, //insert 
    updateUser, updateItem, updateIssueCategory, updateVideo, updateMaster, updateSetting,//update
    deleteItem
} = require('./api')

router.post('/adduser', onSignUp);
router.post('/addmaster', upload.single('master'), addMaster);
router.post('/updatemaster', upload.single('master'), updateMaster);
router.post('/loginbyid', onLoginById);
router.post('/logout', onLogout);
router.get('/auth', getUserToken);
router.get('/users', getUsers);
router.post('/addoneword', upload.single('content'), addOneWord);
router.post('/addoneevent', upload.single('content'), addOneEvent);
router.post('/additem', upload.single('content'), addItem);
router.post('/updateitem', upload.single('content'), updateItem);
router.post('/addvideo', addVideo);
router.post('/updatevideo', updateVideo);
router.post('/addissuecategory', addIssueCategory);
router.post('/updateissuecategory', updateIssueCategory);
router.post('/addimage', upload.single('note'), addNoteImage);
router.post('/deleteitem', deleteItem);
router.post('/updateuser', updateUser);
router.get('/oneword', getOneWord);
router.get('/oneevent', getOneEvent);
router.get('/items', getItems);
router.get('/item', getItem);
router.get('/gethomecontent', getHomeContent);
router.post('/updatesetting', upload.single('master'), updateSetting);
router.post('/addsetting', upload.single('master'), addSetting);
router.get('/setting', getSetting);
module.exports = router;