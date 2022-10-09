const fs = require('fs')
const express = require('express')
const app = express()
const mysql = require('mysql')
const cors = require('cors')
const db = require('./config/db')
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const https = require('https')
const port = 8001;
app.use(cors());
const http = require('http')
require('dotenv').config()
//passport, jwt
const jwt = require('jsonwebtoken')
const { checkLevel, logRequestResponse, isNotNullOrUndefined, namingImagesPath, nullResponse, lowLevelResponse, response, returnMoment } = require('./util')
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
//multer
const { upload } = require('./config/multerConfig')
//express
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// app.use(passport.initialize());
// app.use(passport.session());
// passportConfig(passport);
const schedule = require('node-schedule');

const path = require('path');
app.set('/routes', __dirname + '/routes');
app.use('/config', express.static(__dirname + '/config'));
//app.use('/image', express.static('./upload'));
app.use('/image', express.static(__dirname + '/image'));
app.use('/api', require('./routes/router'))

app.get('/', (req, res) => {
        console.log("back-end initialized")
        res.send('back-end initialized')
});
const is_test = true;

const HTTP_PORT = 8001;
const HTTPS_PORT = 8443;
const dbQueryList = (sql, list) => {
        return new Promise((resolve, reject) => {
                db.query(sql, list, (err, result, fields) => {
                        if (err) {
                                console.log(sql)
                                console.log(err)
                                reject({
                                        code: -200,
                                        result: result
                                })
                        }
                        else {
                                resolve({
                                        code: 200,
                                        result: result
                                })
                        }
                })
        })
}
// let time = new Date(returnMoment())
// console.log(time)
// time.setMinutes(time.getMinutes() + 5)
// console.log(time)
const scheduleAlarm = () => {
        schedule.scheduleJob('0 0/1 * * * *', async function () {
                console.log(returnMoment());
                let date = returnMoment().substring(0, 10);
                let time = returnMoment().substring(11, 16);
                let dayOfWeek = new Date(date).getDay()
                let result = await dbQueryList(`SELECT * FROM alarm_table WHERE DATEDIFF(?, start_date) >= 0 AND days LIKE '%${dayOfWeek}%' AND status=1 AND type=1 `, [date]);
                console.log(result)
                if (result.code > 0) {
                        let list = [...result.result];
                        for (var i = 0; i < list.length; i++) {
                                let item = date + ' ' + list[i].time;
                                console.log(item)
                                item = new Date(item)
                                let moment = returnMoment();
                                console.log(moment)
                                moment = new Date(moment);
                                let fiveMoreMinute = new Date(returnMoment());
                                console.log(fiveMoreMinute)
                                fiveMoreMinute.setMinutes(fiveMoreMinute.getMinutes()+5);
                                console.log(item)
                                console.log(moment)
                                console.log(fiveMoreMinute)
                        }
                }
        })
}
if (is_test) {
        http.createServer(app).listen(HTTP_PORT, function () {
                console.log("Server on " + HTTP_PORT)
                //scheduleAlarm();
        });

} else {
        const options = { // letsencrypt로 받은 인증서 경로를 입력해 줍니다.
                ca: fs.readFileSync("/etc/letsencrypt/live/weare-first.com/fullchain.pem"),
                key: fs.readFileSync("/etc/letsencrypt/live/weare-first.com/privkey.pem"),
                cert: fs.readFileSync("/etc/letsencrypt/live/weare-first.com/cert.pem")
        };
        https.createServer(options, app).listen(HTTPS_PORT, function () {
                console.log("Server on " + HTTPS_PORT);
                //scheduleAlarm();
        });

}


// Default route for server status
app.get('/', (req, res) => {
        res.json({ message: `Server is running on port ${req.secure ? HTTPS_PORT : HTTP_PORT}` });
});


//https.createServer(options, app).listen(HTTPS_PORT);
