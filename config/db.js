const mysql = require('mysql')

const db = mysql.createConnection({
    host : "210.114.1.28",
    user : 'root',
    password : 'qjfwk100djr!',
    port : 3306,
    database:'stock_integrated',
    timezone: 'Asia/Seoul'
})
db.connect();

module.exports = db;