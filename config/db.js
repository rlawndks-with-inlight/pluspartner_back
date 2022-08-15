const mysql = require('mysql')

const db = mysql.createConnection({
    host : "coupon22.cafe24.com",
    user : 'root',
    password : 'qjfwk100djr!',
    port : 3306,
    database:'stock_integrated',
    timezone: 'Asia/Seoul'
})
db.connect();

module.exports = db;