const express = require('express')
//const { json } = require('body-parser')
const router = express.Router()
const cors = require('cors')
router.use(cors())
router.use(express.json())

const crypto = require('crypto')
//const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const when = require('when')

const { checkLevel, getSQLnParams, getUserPKArrStrWithNewPK,
    isNotNullOrUndefined, namingImagesPath, nullResponse,
    lowLevelResponse, response, removeItems, returnMoment, formatPhoneNumber, categoryToNumber, sendAlarm, makeMaxPage
} = require('../util')
const {
    getRowsNumWithKeyword, getRowsNum, getAllDatas,
    getDatasWithKeywordAtPage, getDatasAtPage,
    getKioskList, getItemRows, getItemList, dbQueryList, dbQueryRows, insertQuery, getTableAI
} = require('../query-util')
const macaddress = require('node-macaddress');

const db = require('../config/db')
const { upload } = require('../config/multerConfig')
const { Console, table } = require('console')
const { abort } = require('process')
const axios = require('axios')
//const { pbkdf2 } = require('crypto')
const salt = "435f5ef2ffb83a632c843926b35ae7855bc2520021a73a043db41670bfaeb722"
const saltRounds = 10
const pwBytes = 64
const jwtSecret = "djfudnsqlalfKeyFmfRkwu"
const { format, formatDistance, formatRelative, subDays } = require('date-fns')
const geolocation = require('geolocation')
const kakaoOpt = {
    clientId: '4a8d167fa07331905094e19aafb2dc47',
    redirectUri: 'http://172.30.1.19:8001/api/kakao/callback',
};
router.get('/', (req, res) => {
    console.log("back-end initialized")
    res.send('back-end initialized')
});


const addAlarm = (req, res) => {
    try {
        // 바로할지, 0-1, 요일, 시간, 
        const { title, note, url, type, start_date, days, time } = req.body;


        db.query("INSERT INTO alarm_table (title, note, url, type, start_date, days, time) VALUES (?, ?, ?, ?, ?, ?, ?)", [title, note, url, type, start_date, days, time], async (err, result) => {
            if (err) {
                console.log(err)
                response(req, res, -200, "알람 추가 실패", [])
            }
            else {
                if (type == 0) {
                    sendAlarm(title, note, "alarm", result.insertId, url);
                    insertQuery("INSERT INTO alarm_log_table (title, note, item_table, item_pk, url) VALUES (?, ?, ?, ?, ?)", [title, note, "alarm", result.insertId, url])
                }
                await db.query("UPDATE alarm_table SET sort=? WHERE pk=?", [result.insertId, result.insertId], (err, result) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "알람 추가 실패", [])
                    }
                    else {
                        response(req, res, 200, "알람 추가 성공", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        response(req, res, -200, "서버 에러 발생", [])
    }
}
const getNoticeAndAlarmLastPk = (req, res) => {
    try {
        db.query("SELECT * FROM alarm_log_table ORDER BY pk DESC LIMIT 1", async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버에러발생", [])
            }
            else {
                await db.query("SELECT * FROM notice_table ORDER BY pk DESC LIMIT 1", (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버에러발생", [])

                    }
                    else {
                        return response(req, res, 100, "success", { alarm_last_pk: result[0]?.pk ?? 0, notice_last_pk: result2[0]?.pk ?? 0 })
                    }
                })
            }
        })
    } catch (e) {

    }
}
const updateAlarm = (req, res) => {
    try {
        // 바로할지, 0-1, 요일, 시간, 
        const { title, note, url, type, start_date, days, time, pk } = req.body;
        db.query("UPDATE alarm_table SET title=?, note=?, url=?, type=?, start_date=?, days=?, time=? WHERE pk=?", [title, note, url, type, start_date, days, time, pk], (err, result) => {
            if (err) {
                console.log(err)
                response(req, res, -200, "알람 수정 실패", [])
            }
            else {
                response(req, res, 200, "알람 수정 성공", [])
            }
        })

    } catch (err) {
        console.log(err)
        response(req, res, -200, "서버 에러 발생", [])
    }
}
const onSignUp = async (req, res) => {
    try {

        //logRequest(req)
        const id = req.body.id ?? "";
        const pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const phone = req.body.phone ?? "";
        const user_level = req.body.user_level ?? 0;
        const type_num = req.body.type_num ?? 0;
        const profile_img = req.body.profile_img ?? "";
        //중복 체크 
        let sql = "SELECT * FROM user_table WHERE id=? OR nickname=? OR user_level=? "

        db.query(sql, [id, nickname, -10], (err, result) => {
            if (result.length > 0) {
                let msg = "";
                let i = 0;
                for (i = 0; i < result.length; i++) {
                    if (result[i].id == id) {
                        msg = "아이디가 중복됩니다.";
                        break;
                    }
                    if (result[i].nickname == nickname) {
                        msg = "닉네임이 중복됩니다.";
                        break;
                    }
                    if (result[i].user_level == -10 && result[i].phone == phone) {
                        msg = "가입할 수 없습니다.";
                        break;
                    }
                }
                if (i != result.length) {
                    return response(req, res, -200, msg, [])
                }
            } else {
                crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')

                    if (err) {
                        console.log(err)
                        response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    }

                    sql = 'INSERT INTO user_table (id, pw, name, nickname , phone, user_level, type, profile_img) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
                    await db.query(sql, [id, hash, name, nickname, phone, user_level, type_num, profile_img], async (err, result) => {

                        if (err) {
                            console.log(err)
                            response(req, res, -200, "회원 추가 실패", [])
                        }
                        else {
                            await db.query("UPDATE user_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                                if (err) {
                                    console.log(err)
                                    response(req, res, -200, "회원 추가 실패", [])
                                }
                                else {
                                    response(req, res, 200, "회원 추가 성공", [])
                                }
                            })
                        }
                    })
                })
            }
        })

    } catch (err) {
        console.log(err)
        response(req, res, -200, "서버 에러 발생", [])
    }
}
const onLoginById = async (req, res) => {
    try {
        let { id, pw } = req.body;
        db.query('SELECT * FROM user_table WHERE id=?', [id], async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result1.length > 0) {
                    await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                        // bcrypt.hash(pw, salt, async (err, hash) => {
                        let hash = decoded.toString('base64');
                        if (hash == result1[0].pw) {
                            try {
                                const token = jwt.sign({
                                    pk: result1[0].pk,
                                    nickname: result1[0].nickname,
                                    id: result1[0].id,
                                    user_level: result1[0].user_level,
                                    phone: result1[0].phone,
                                    profile_img: result1[0].profile_img,
                                    type: result1[0].type
                                },
                                    jwtSecret,
                                    {
                                        expiresIn: '6000m',
                                        issuer: 'fori',
                                    });
                                res.cookie("token", token, { httpOnly: true, maxAge: 60 * 60 * 1000 * 10 });
                                db.query('UPDATE user_table SET last_login=? WHERE pk=?', [returnMoment(), result1[0].pk], (err, result) => {
                                    if (err) {
                                        console.log(err)
                                        return response(req, res, -200, "서버 에러 발생", [])
                                    }
                                })
                                return response(req, res, 200, result1[0].nickname + ' 님 환영합니다.', result1[0]);
                            } catch (e) {
                                console.log(e)
                                return response(req, res, -200, "서버 에러 발생", [])
                            }
                        } else {
                            return response(req, res, -100, "아이디 또는 비밀번호를 확인해주세요.", [])

                        }
                    })
                } else {
                    return response(req, res, -100, "아이디 또는 비밀번호를 확인해주세요.", [])
                }
            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onLoginBySns = (req, res) => {
    try {
        let { id, typeNum, name, nickname, phone, user_level, profile_img } = req.body;
        db.query("SELECT * FROM user_table WHERE id=? AND type=?", [id, typeNum], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {//기존유저
                    let token = jwt.sign({
                        pk: result[0].pk,
                        nickname: result[0].nickname,
                        id: result[0].id,
                        user_level: result[0].user_level,
                        phone: result[0].phone,
                        profile_img: result[0].profile_img,
                        type: typeNum
                    },
                        jwtSecret,
                        {
                            expiresIn: '6000m',
                            issuer: 'fori',
                        });
                    res.cookie("token", token, { httpOnly: true, maxAge: 60 * 60 * 1000 * 10 });
                    await db.query('UPDATE user_table SET last_login=? WHERE pk=?', [returnMoment(), result[0].pk], (err, result) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        }
                    })
                    return response(req, res, 200, result[0].nickname + ' 님 환영합니다.', result[0]);
                } else {//신규유저
                    return response(req, res, 50, '신규회원 입니다.', []);
                }
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const onLoginByPhone = (req, res) => {
    try {

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const uploadProfile = (req, res) => {
    try {
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        const id = req.body.id;
        db.query('UPDATE user_table SET profile_img=? WHERE id=?', [image, id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const editMyInfo = (req, res) => {
    try {
        let { pw, nickname, newPw, phone, id } = req.body;
        crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
            // bcrypt.hash(pw, salt, async (err, hash) => {
            let hash = decoded.toString('base64')

            if (err) {
                console.log(err)
                response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
            }

            await db.query("SELECT * FROM user_table WHERE id=? AND pw=?", [id, hash], async (err, result) => {
                if (err) {
                    console.log(err);
                    response(req, res, -100, "서버 에러 발생", [])
                } else {
                    if (result.length > 0) {
                        if (newPw) {
                            await crypto.pbkdf2(newPw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                                // bcrypt.hash(pw, salt, async (err, hash) => {
                                let new_hash = decoded.toString('base64')
                                if (err) {
                                    console.log(err)
                                    response(req, res, -200, "새 비밀번호 암호화 도중 에러 발생", [])
                                }
                                await db.query("UPDATE user_table SET pw=? WHERE id=?", [new_hash, id], (err, result) => {
                                    if (err) {
                                        console.log(err)
                                        return response(req, res, -100, "서버 에러 발생", []);
                                    } else {
                                        return response(req, res, 100, "success", []);
                                    }
                                })
                            })
                        } else if (nickname || phone) {
                            let selectSql = "";
                            let updateSql = "";
                            let zColumn = [];
                            if (nickname) {
                                selectSql = "SELECT * FROM user_table WHERE nickname=? AND id!=?"
                                updateSql = "UPDATE user_table SET nickname=? WHERE id=?";
                                zColumn.push(nickname);
                            } else if (phone) {
                                selectSql = "SELECT * FROM user_table WHERE phone=? AND id!=?"
                                updateSql = "UPDATE user_table SET phone=? WHERE id=?";
                                zColumn.push(phone);
                            }
                            zColumn.push(id);
                            await db.query(selectSql, zColumn, async (err, result1) => {
                                if (err) {
                                    console.log(err)
                                    return response(req, res, -100, "서버 에러 발생", []);
                                } else {
                                    if (result1.length > 0) {
                                        let message = "";
                                        if (nickname) {
                                            message = "이미 사용중인 닉네임 입니다.";
                                        } else if (phone) {
                                            message = "이미 사용중인 전화번호 입니다.";
                                        }
                                        return response(req, res, -50, message, []);
                                    } else {
                                        await db.query(updateSql, zColumn, (err, result2) => {
                                            if (err) {
                                                console.log(err)
                                                return response(req, res, -100, "서버 에러 발생", []);
                                            } else {
                                                return response(req, res, 100, "success", []);
                                            }
                                        })
                                    }
                                }
                            })
                        }
                    } else {
                        response(req, res, -50, "비밀번호가 일치하지 않습니다.", [])
                    }
                }
            })
        })


    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onResign = (req, res) => {
    try {
        let { id } = req.body;
        db.query("DELETE FROM user_table WHERE id=?", [id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -100, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const kakaoCallBack = (req, res) => {
    try {
        const token = req.body.token;
        async function kakaoLogin() {
            let tmp;

            try {
                const url = 'https://kapi.kakao.com/v2/user/me';
                const Header = {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                };
                tmp = await axios.get(url, Header);
            } catch (e) {
                console.log(e);
                response(req, res, -200, "서버 에러 발생", [])
            }

            try {
                const { data } = tmp;
                const { id, properties } = data;
                response(req, res, 100, "success", { id, properties });

            } catch (e) {
                console.log(e);
                response(req, res, -100, "서버 에러 발생", [])
            }

        }
        kakaoLogin();

    } catch (err) {
        console.log(err)
        response(req, res, -200, "서버 에러 발생", [])
    }
}



const sendAligoSms = ({ receivers, message }) => {
    return axios.post('https://apis.aligo.in/send/', null, {
        params: {
            key: 'xbyndmadqxp8cln66alygdq12mbpj7p7',
            user_id: 'firstpartner',
            sender: '1522-1233',
            receiver: receivers.join(','),
            msg: message
        },
    }).then((res) => res.data).catch(err => {
        console.log('err', err);
    });
}
const sendSms = (req, res) => {
    try {
        let receiver = req.body.receiver;
        const content = req.body.content;
        sendAligoSms({ receivers: receiver, message: content }).then((result) => {
            if (result.result_code == '1') {
                return response(req, res, 100, "success", [])
            } else {
                return response(req, res, -100, "fail", [])
            }
        });
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const findIdByPhone = (req, res) => {
    try {
        const phone = req.body.phone;
        db.query("SELECT pk, id FROM user_table WHERE phone=?", [phone], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const findAuthByIdAndPhone = (req, res) => {
    try {
        const id = req.body.id;
        const phone = req.body.phone;
        db.query("SELECT * FROM user_table WHERE id=? AND phone=?", [id, phone], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {
                    return response(req, res, 100, "success", result[0]);
                } else {
                    return response(req, res, -50, "아이디 또는 비밀번호를 확인해주세요.", []);
                }
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const checkExistId = (req, res) => {
    try {
        const id = req.body.id;
        db.query(`SELECT * FROM user_table WHERE id=? `, [id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {
                    return response(req, res, -50, "이미 사용중인 아이디입니다.", []);
                } else {
                    return response(req, res, 100, "사용가능한 아이디입니다.", []);
                }
            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const checkExistNickname = (req, res) => {
    try {
        const nickname = req.body.nickname;
        db.query(`SELECT * FROM user_table WHERE nickname=? `, [nickname], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {
                    return response(req, res, -50, "이미 사용중인 닉네임입니다.", []);
                } else {
                    return response(req, res, 100, "사용가능한 닉네임입니다.", []);
                }
            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const changePassword = (req, res) => {
    try {
        const id = req.body.id;
        let pw = req.body.pw;
        crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
            // bcrypt.hash(pw, salt, async (err, hash) => {
            let hash = decoded.toString('base64')

            if (err) {
                console.log(err)
                response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
            }

            await db.query("UPDATE user_table SET pw=? WHERE id=?", [hash, id], (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", [])
                }
            })
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUserToken = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0)
        if (decode) {
            let pk = decode.pk;
            let nickname = decode.nickname;
            let id = decode.id;
            let phone = decode.phone;
            let user_level = decode.user_level;
            let profile_img = decode.profile_img;
            let type = decode.type;
            res.send({ id, pk, nickname, phone, user_level, profile_img, type })
        }
        else {
            res.send({
                pk: -1,
                level: -1
            })
        }
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onLogout = (req, res) => {
    try {
        res.clearCookie('token')
        //res.clearCookie('rtoken')
        return response(req, res, 200, "로그아웃 성공", [])
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUsers = (req, res) => {
    try {
        let sql = "SELECT * FROM user_table ";
        let pageSql = "SELECT COUNT(*) FROM user_table ";
        let page_cut = req.query.page_cut;
        let status = req.query.status;
        let keyword = req.query.keyword;
        let userType = req.query.userType;
        let whereStr = " WHERE 1=1 ";
        if (req.query.level) {
            if (req.query.level == 0) {
                whereStr += ` AND user_level <= ${req.query.level} `;
            } else {
                whereStr += ` AND user_level=${req.query.level} `;
            }
        }
        if(userType){
            whereStr += ` AND type=${userType} `;
        }
        if (status) {
            whereStr += ` AND status=${status} `;
        }
        if (keyword) {
            whereStr += ` AND (id LIKE '%${keyword}%' OR name LIKE '%${keyword}%' OR nickname LIKE '%${keyword}%' OR phone LIKE '%${keyword}%')`;
        }
        if (!page_cut) {
            page_cut = 15
        }
        pageSql = pageSql + whereStr;
        sql = sql + whereStr + " ORDER BY sort DESC ";
        if (req.query.page) {
            sql += ` LIMIT ${(req.query.page - 1) * page_cut}, ${page_cut}`;
            db.query(pageSql, async (err, result1) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    await db.query(sql, (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {
                            let maxPage = result1[0]['COUNT(*)'] % page_cut == 0 ? (result1[0]['COUNT(*)'] / page_cut) : ((result1[0]['COUNT(*)'] - result1[0]['COUNT(*)'] % page_cut) / page_cut + 1);
                            return response(req, res, 100, "success", { data: result2, maxPage: maxPage });
                        }
                    })
                }
            })
        } else {
            db.query(sql, (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", result)
                }
            })
        }
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const updateUser = async (req, res) => {
    try {
        const id = req.body.id ?? "";
        let pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const phone = req.body.phone ?? "";
        const user_level = req.body.user_level ?? 0;
        const pk = req.body.pk ?? 0;
        if (pw) {
            await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                // bcrypt.hash(pw, salt, async (err, hash) => {
                let hash = decoded.toString('base64')
                if (err) {
                    console.log(err)
                    response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                } else {
                    await db.query("UPDATE user_table SET pw=? WHERE pk=?", [hash, pk], (err, result) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "비밀번호 insert중 에러발생", [])
                        } else {
                        }
                    })
                }
            })
        }
        await db.query("UPDATE user_table SET id=?, name=?, nickname=?, phone=?, user_level=? WHERE pk=?", [id, name, nickname, phone, user_level, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버에러발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const addMaster = (req, res) => {
    try {
        const id = req.body.id ?? "";
        const pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const user_level = req.body.user_level ?? 30;
        const masterImg = '/image/' + req.files.master[0].fieldname + '/' + req.files.master[0].filename;
        const channelImg = '/image/' + req.files.channel[0].fieldname + '/' + req.files.channel[0].filename;
        //중복 체크 
        let sql = "SELECT * FROM user_table WHERE id=?"

        db.query(sql, [id], (err, result) => {
            if (result.length > 0)
                response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')

                    if (err) {
                        console.log(err)
                        response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    }

                    sql = 'INSERT INTO user_table (id, pw, name, nickname, user_level, profile_img, channel_img) VALUES (?, ?, ?, ?, ?, ?, ?)'
                    await db.query(sql, [id, hash, name, nickname, user_level, masterImg, channelImg], async (err, result) => {

                        if (err) {
                            console.log(err)
                            response(req, res, -200, "회원 추가 실패", [])
                        }
                        else {
                            await db.query("UPDATE user_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                                if (err) {
                                    console.log(err)
                                    response(req, res, -200, "회원 추가 실패", [])
                                }
                                else {
                                    response(req, res, 200, "회원 추가 성공", [])
                                }
                            })
                        }
                    })
                })
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateMaster = (req, res) => {
    try {
        const id = req.body.id ?? "";
        let pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const pk = req.body.pk;
        let masterImg = "";
        let channelImg = "";
        let sql = "SELECT * FROM user_table WHERE id=? AND pk!=?"
        db.query(sql, [id, pk], async (err, result) => {
            if (result?.length > 0)
                response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                let columns = " id=?, name=?, nickname=? ";
                let zColumn = [id, name, nickname];
                await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    } else {
                        if (pw) {
                            columns += ", pw =?"
                            zColumn.push(hash);
                        }
                        if (req.files.master) {
                            masterImg = '/image/' + req.files.master[0].fieldname + '/' + req.files.master[0].filename;
                            columns += ", profile_img=?"
                            zColumn.push(masterImg);
                        }
                        if (req.files.channel) {
                            channelImg = '/image/' + req.files.channel[0].fieldname + '/' + req.files.channel[0].filename;
                            columns += ", channel_img=?"
                            zColumn.push(channelImg);
                        }
                        zColumn.push(pk)
                        await db.query(`UPDATE user_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", [])
                            }
                        })
                    }
                })

            }
        })

    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addChannel = (req, res) => {
    try {
        const id = req.body.id ?? "";
        const pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const user_level = req.body.user_level ?? 25;
        let image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        let sql = "SELECT * FROM user_table WHERE id=?"

        db.query(sql, [id], (err, result) => {
            if (result.length > 0)
                response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')

                    if (err) {
                        console.log(err)
                        response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    }

                    sql = 'INSERT INTO user_table (id, pw, name, nickname, user_level, channel_img) VALUES (?, ?, ?, ?, ?, ?)'
                    await db.query(sql, [id, hash, name, nickname, user_level, image], async (err, result) => {

                        if (err) {
                            console.log(err)
                            response(req, res, -200, "fail", [])
                        }
                        else {
                            await db.query("UPDATE user_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                                if (err) {
                                    console.log(err)
                                    response(req, res, -200, "fail", [])
                                }
                                else {
                                    response(req, res, 200, "success", [])
                                }
                            })
                        }
                    })
                })
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateChannel = (req, res) => {
    try {
        let nickname = req.body.nickname;
        const pk = req.body.pk;
        let image = "";
        let columns = " nickname=? ";
        let zColumn = [nickname];
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            columns += ", channel_img=? ";
            zColumn.push(image);
        }
        zColumn.push(pk);
        db.query(`UPDATE user_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                response(req, res, -200, "fail", [])
            }
            else {
                response(req, res, 200, "성공적으로 수정되었습니다.", [])
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getHomeContent = async (req, res) => {
    try {
        let result_list = [];
        let sql_list = ['SELECT * FROM setting_table ORDER BY pk DESC LIMIT 1',
            'SELECT * FROM user_table WHERE user_level=30 AND status=1 ORDER BY sort DESC',
            'SELECT pk, title, hash FROM oneword_table WHERE status=1 ORDER BY sort DESC LIMIT 1',
            'SELECT pk, title, hash FROM oneevent_table WHERE status=1 ORDER BY sort DESC LIMIT 1',
            'SELECT pk, title, hash, main_img, font_color, background_color, date FROM issue_table WHERE status=1 ORDER BY sort DESC LIMIT 5',
            'SELECT pk, title, hash, main_img, font_color, background_color, date FROM theme_table WHERE status=1 ORDER BY sort DESC LIMIT 5',
            'SELECT pk, title, hash, main_img, font_color, background_color, date FROM strategy_table WHERE status=1 ORDER BY sort DESC LIMIT 3',
            'SELECT pk, title, hash, main_img, font_color, background_color, date FROM feature_table WHERE status=1 ORDER BY sort DESC LIMIT 5',
            'SELECT pk, title, font_color, background_color, link FROM video_table WHERE status=1 ORDER BY sort DESC LIMIT 5'];

        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise('', sql_list[i]));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        return response(req, res, 100, "success", { setting: (await result[0])?.data[0] ?? {}, masters: (await result[1])?.data ?? [], oneWord: (await result[2])?.data[0] ?? {}, oneEvent: (await result[3])?.data[0] ?? {}, issues: (await result[4])?.data ?? [], themes: (await result[5])?.data ?? [], strategies: (await result[6])?.data ?? [], features: (await result[7])?.data ?? [], videos: (await result[8])?.data ?? [] })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getChannelList = (req, res) => {
    try {
        db.query("SELECT * FROM user_table WHERE user_level IN (25, 30) ", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result)
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getVideo = (req, res) => {
    try {
        const pk = req.params.pk;
        let sql = `SELECT video_table.* , user_table.nickname, user_table.name FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk WHERE video_table.pk=${pk} LIMIT 1`;
        db.query(sql, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                let relate_video = JSON.parse(result[0].relate_video);
                relate_video = relate_video.join();
                await db.query(`SELECT title, date, pk FROM video_table WHERE pk IN (${relate_video})`, (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        return response(req, res, 100, "success", { video: result[0], relate: result2 })
                    }
                })
            }
        })
        db.query(sql)
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getVideoContent = (req, res) => {
    try {
        const pk = req.query.pk;
        let sql1 = `SELECT video_table.* , user_table.nickname, user_table.name FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk WHERE video_table.pk=? LIMIT 1`;//비디오 정보
        let sql2 = `SELECT video_relate_table.*, video_table.* FROM video_relate_table LEFT JOIN video_table ON video_relate_table.relate_video_pk = video_table.pk WHERE video_relate_table.video_pk=? `//관련영상
        let sql3 = `SELECT video_table.pk, video_table.link, video_table.title, user_table.name, user_table.nickname FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk ORDER BY pk DESC LIMIT 5`;//최신영상
        if (req.query.views) {
            db.query("UPDATE video_table SET views=views+1 WHERE pk=?", [pk], (err, result_view) => {
                if (err) {
                    console.log(err)
                    response(req, res, -200, "서버 에러 발생", [])
                } else {
                }
            })
        }
        db.query(sql1, [pk], async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query(sql2, [pk], async (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        await db.query(sql3, async (err, result3) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", {
                                    video: result1[0],
                                    relates: result2,
                                    latests: result3
                                })
                            }
                        })
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getComments = (req, res) => {
    try {
        const { pk, category } = req.query;
        let zColumn = [];
        let columns = ""
        if (pk) {
            zColumn.push(pk)
            columns += " AND comment_table.item_pk=? ";
        }
        if (category) {
            zColumn.push(category)
            columns += " AND comment_table.category_pk=? ";
        }
        db.query(`SELECT comment_table.*, user_table.nickname, user_table.profile_img FROM comment_table LEFT JOIN user_table ON comment_table.user_pk = user_table.pk WHERE 1=1 ${columns} ORDER BY pk DESC`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                response(req, res, -200, "fail", [])
            }
            else {
                response(req, res, 200, "success", result)
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addComment = (req, res) => {
    try {
        const { userPk, userNick, pk, parentPk, title, note, category } = req.body;
        db.query("INSERT INTO comment_table (user_pk, user_nickname, item_pk, item_title, note, category_pk, parent_pk) VALUES (?, ?, ?, ?, ?, ?, ?)", [userPk, userNick, pk, title, note, category, parentPk], (err, result) => {
            if (err) {
                console.log(err)
                response(req, res, -200, "fail", [])
            }
            else {
                response(req, res, 200, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateComment = (req, res) => {
    try {

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getCommentsManager = (req, res) => {
    try {
        let sql = `SELECT COUNT(*) FROM comment_table `
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addOneWord = (req, res) => {
    try {
        const { title, hash, suggest_title, note, user_pk } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk];
        let columns = "(title, hash, suggest_title, note, user_pk";
        let values = "(?, ?, ?, ?, ?";
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        } else {
            image = req.body.url ?? "";
        }
        zColumn.push(image);
        columns += ', main_img)'
        values += ',?)'
        db.query(`INSERT INTO oneword_table ${columns} VALUES ${values}`, zColumn, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query("UPDATE oneword_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })

            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addOneEvent = (req, res) => {
    try {
        const { title, hash, suggest_title, note, user_pk } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk];
        let columns = "(title, hash, suggest_title, note, user_pk";
        let values = "(?, ?, ?, ?, ?";
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        } else {
            image = req.body.url ?? "";
        }
        zColumn.push(image);
        columns += ', main_img)'
        values += ',?)'
        db.query(`INSERT INTO oneevent_table ${columns} VALUES ${values}`, zColumn, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE oneevent_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getKoreaByEng = (str) => {
    let ans = "";
    if (str == 'oneword') {
        ans = "하루1단어: ";
    } else if (str == 'oneevent') {
        ans = "하루1종목: ";
    } else if (str == 'theme') {
        ans = "핵심테마: ";
    } else if (str == 'strategy') {
        ans = "전문가칼럼: ";
    } else if (str == 'issue') {
        ans = "핵심이슈: ";
    } else if (str == 'feature') {
        ans = "특징주: ";
    }
    return ans;
}
const addItem = (req, res) => {
    try {
        const { title, hash, suggest_title, want_push, note, user_pk, table, category, font_color, background_color, note_align } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk, font_color, background_color, note_align];
        let columns = "(title, hash, suggest_title, note, user_pk, font_color, background_color, note_align";
        let values = "(?, ?, ?, ?, ?, ?, ?, ?";
        if (category) {
            zColumn.push(category);
            columns += ', category_pk '
            values += ' ,? '
        }
        let content_image = "";
        let content2_image = "";
        if (req.files.content) {
            content_image = '/image/' + req.files.content[0].fieldname + '/' + req.files.content[0].filename;
            zColumn.push(content_image);
            columns += ', main_img';
            values += ', ?';
        }
        if (req.files.content2) {
            content2_image = '/image/' + req.files.content2[0].fieldname + '/' + req.files.content2[0].filename;
            zColumn.push(content2_image);
            columns += ', second_img';
            values += ', ?';
        }
        columns += ')';
        values += ')';
        db.query(`INSERT INTO ${table}_table ${columns} VALUES ${values}`, zColumn, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                if (want_push == 1) {
                    sendAlarm(`${getKoreaByEng(table) + title}`, "", "notice", result.insertId, `/post/${table}/${result.insertId}`);
                }
                await db.query(`UPDATE ${table}_table SET sort=? WHERE pk=?`, [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateItem = (req, res) => {
    try {
        const { title, hash, suggest_title, note, user_pk, table, category, font_color, background_color, note_align, pk } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk, font_color, background_color, note_align];
        let columns = " title=?, hash=?, suggest_title=?, note=?, user_pk=?, font_color=?, background_color=?, note_align=? ";
        if (category) {
            zColumn.push(category);
            columns += ', category_pk=? '
        }
        let content_image = "";
        let content2_image = "";
        if (req.files.content) {
            content_image = '/image/' + req.files.content[0].fieldname + '/' + req.files.content[0].filename;
            zColumn.push(content_image);
            columns += ', main_img=?';
        }
        if (req.files.content2) {
            content2_image = '/image/' + req.files.content2[0].fieldname + '/' + req.files.content2[0].filename;
            zColumn.push(content2_image);
            columns += ', second_img=?';
        }
        zColumn.push(pk)
        db.query(`UPDATE ${table}_table SET ${columns} WHERE pk=? `, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addIssueCategory = (req, res) => {
    try {
        const { title, sub_title } = req.body;
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        }
        db.query("INSERT INTO issue_category_table (title,sub_title,main_img) VALUES (?,?,?)", [title, sub_title, image], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE issue_category_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateIssueCategory = (req, res) => {
    try {
        const { title, sub_title, pk } = req.body;
        let zColumn = [title, sub_title];
        let columns = " title=?, sub_title=? ";

        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            zColumn.push(image);
            columns += ', main_img=? '
        }
        zColumn.push(pk)
        db.query(`UPDATE issue_category_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addFeatureCategory = (req, res) => {
    try {
        const { title, sub_title } = req.body;
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        }
        db.query("INSERT INTO feature_category_table (title,sub_title,main_img) VALUES (?,?,?)", [title, sub_title, image], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE feature_category_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateFeatureCategory = (req, res) => {
    try {
        const { title, sub_title, pk } = req.body;
        let zColumn = [title, sub_title];
        let columns = " title=?, sub_title=? ";

        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            zColumn.push(image);
            columns += ', main_img=? '
        }
        zColumn.push(pk)
        db.query(`UPDATE feature_category_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getItem = (req, res) => {
    try {
        let table = req.query.table ?? "user";
        let pk = req.query.pk ?? 0;
        let whereStr = " WHERE pk=? ";
        if (table == "setting") {
            whereStr = "";
        }

        let sql = `SELECT * FROM ${table}_table ` + whereStr;

        if (table != "user" && table != "issue_category" && table != "feature_category" && table != "alarm") {
            sql = `SELECT ${table}_table.* , user_table.nickname, user_table.name FROM ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk = user_table.pk WHERE ${table}_table.pk=? LIMIT 1`
        }
        if (req.query.views) {
            db.query(`UPDATE ${table}_table SET views=views+1 WHERE pk=?`, [pk], (err, result_view) => {
                if (err) {
                    console.log(err)
                    response(req, res, -200, "서버 에러 발생", [])
                } else {
                }
            })
        }
        db.query(sql, [pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (categoryToNumber(table) != -1) {
                    return response(req, res, 100, "success", result[0])
                } else {
                    return response(req, res, 100, "success", result[0])
                }
            }
        })

    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const addVideo = (req, res) => {
    try {
        const { user_pk, title, link, note,want_push, font_color, background_color, relate_video, note_align } = req.body;
        db.query("INSERT INTO video_table (user_pk, title, link, note, font_color, background_color, note_align) VALUES (?, ?, ?, ?, ?, ?, ?)", [user_pk, title, link, note, font_color, background_color, note_align], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (want_push == 1) {
                    sendAlarm(`${title}`, "", "video", result.insertId, `/post/video/${result.insertId}`);
                }
                await db.query("UPDATE video_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                })
                let relate_videos = JSON.parse(relate_video)
                if (relate_videos.length > 0) {
                    let relate_list = [];
                    for (var i = 0; i < relate_videos.length; i++) {
                        relate_list[i] = [result?.insertId, relate_videos[i]];
                    }
                    await db.query("INSERT INTO video_relate_table (video_pk, relate_video_pk) VALUES ? ", [relate_list], async (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {

                        }
                    })
                } else {
                    return response(req, res, 100, "success", [])
                }
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateVideo = (req, res) => {
    try {
        const { user_pk, title, link, note, font_color, background_color, relate_video, note_align, pk } = req.body;
        db.query("UPDATE video_table SET user_pk=?, title=?, link=?, note=?, font_color=?, background_color=?, note_align=? WHERE pk=?", [user_pk, title, link, note, font_color, background_color, note_align, pk], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query("DELETE FROM video_relate_table WHERE video_pk=?", [pk], async (err, result1) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        let relate_videos = JSON.parse(relate_video)
                        if (relate_videos.length > 0) {
                            let relate_list = [];
                            for (var i = 0; i < relate_videos.length; i++) {
                                relate_list[i] = [pk, relate_videos[i]];
                            }
                            await db.query("INSERT INTO video_relate_table (video_pk, relate_video_pk) VALUES ? ", [relate_list], (err, result2) => {
                                if (err) {
                                    console.log(err)
                                    return response(req, res, -200, "서버 에러 발생", [])
                                } else {
                                    return response(req, res, 100, "success", [])
                                }
                            })
                        } else {
                            return response(req, res, 100, "success", [])
                        }

                    }
                })

            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addNotice = (req, res) => {
    try {
        const { title, note, note_align, user_pk } = req.body;
        db.query("INSERT INTO notice_table ( title, note, note_align, user_pk) VALUES (?, ?, ?, ?)", [title, note, note_align, user_pk], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                sendAlarm("공지사항: " + title, "", "notice", result.insertId);
                //insertQuery("INSERT INTO alarm_log_table (title, note, item_table, item_pk) VALUES (?, ?, ?, ?)", [title, "", "notice", result.insertId])
                await db.query("UPDATE notice_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "fail", [])
                    }
                    else {
                        response(req, res, 200, "success", [])
                    }
                })
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateNotice = (req, res) => {
    try {
        const { title, note, note_align, pk } = req.body;
        db.query("UPDATE notice_table SET  title=?, note=?, note_align=? WHERE pk=?", [title, note, note_align, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addNoteImage = (req, res) => {
    try {
        if (req.file) {
            return response(req, res, 100, "success", { filename: `/image/note/${req.file.filename}` })
        } else {
            return response(req, res, -100, "이미지가 비어 있습니다.", [])
        }
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const processParallel = () => {

}
const queryPromise = (table, sql) => {

    return new Promise(async (resolve, reject) => {
        await db.query(sql, (err, result, fields) => {
            if (err) {
                console.log(sql)
                console.log(err)
                reject({
                    code: -200,
                    data: [],
                    table: table
                })
            } else {
                resolve({
                    code: 200,
                    data: result,
                    table: table
                })
            }
        })
    })
}
const onSearchAllItem = async (req, res) => {
    try {
        let keyword = req.query.keyword;

        let sql_list = [];
        let sql_obj = [{ table: 'oneword', column: ['pk', 'title', 'hash'], wheres: ['title', 'hash', 'note'] },
        { table: 'oneevent', column: ['pk', 'title', 'hash'], wheres: ['title', 'hash', 'note'] },
        { table: 'issue', column: ['pk', 'title', 'hash', 'main_img', 'font_color', 'background_color', 'date'], wheres: ['title', 'hash', 'note'] },
        { table: 'feature', column: ['pk', 'title', 'hash', 'main_img', 'font_color', 'background_color', 'date'], wheres: ['title', 'hash', 'note'] },
        { table: 'theme', column: ['pk', 'title', 'hash', 'main_img', 'font_color', 'background_color', 'date'], wheres: ['title', 'hash', 'note'] },
        { table: 'video', column: ['pk', 'title', 'font_color', 'background_color', 'link'], wheres: ['title', 'note'] },
        ]
        for (var i = 0; i < sql_obj.length; i++) {
            let sql = "";
            sql = `SELECT ${sql_obj[i].column.join()} FROM ${sql_obj[i].table}_table WHERE status=1 AND (`;
            for (var j = 0; j < sql_obj[i].wheres.length; j++) {
                if (j != 0) {
                    sql += ` OR `
                }
                sql += ` ${sql_obj[i].wheres[j]} LIKE "%${keyword}%" `
            }
            sql += `) ORDER BY sort DESC LIMIT 8 `;

            sql_list.push(queryPromise(sql_obj[i].table, sql));
        }
        for (var i = 0; i < sql_list.length; i++) {
            await sql_list[i];
        }
        let result = (await when(sql_list));
        return response(req, res, 100, "success", { oneWord: (await result[0])?.data ?? [], oneEvent: (await result[1])?.data ?? [], issues: (await result[2])?.data ?? [], features: (await result[3])?.data ?? [], themes: (await result[4])?.data ?? [], videos: (await result[5])?.data ?? [] });


    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getAllPosts = async (req, res) => {
    try {
        let { keyword, page, order, page_cut } = req.query;
        if (!page_cut) {
            page_cut = 15;
        }
        let sql_list = [];
        let sql_obj = [
            { table: 'oneword', category_num:0 },
            { table: 'oneevent' , category_num:1},
            { table: 'theme', category_num:2 },
            { table: 'strategy', category_num:3 },
            { table: 'issue', category_num:4 },
            { table: 'feature', category_num:5 },
            { table: 'video', category_num:6 },
            { table: 'notice', category_num:7 },
        ]
        for (var i = 0; i < sql_obj.length; i++) {
            let sql = "";
            sql = `SELECT ${sql_obj[i].table}_table.title, ${sql_obj[i].table}_table.date, ${sql_obj[i].table}_table.views, '${sql_obj[i].table}' AS category, (SELECT COUNT(*)  FROM comment_table WHERE comment_table.item_pk=${sql_obj[i].table}_table.pk AND comment_table.category_pk=${sql_obj[i].category_num}) AS comment_num, user_table.nickname FROM ${sql_obj[i].table}_table LEFT JOIN user_table ON ${sql_obj[i].table}_table.user_pk=user_table.pk `;
            if(keyword){
                sql += ` WHERE (${sql_obj[i].table}_table.title LIKE "%${keyword}%" OR user_table.nickname LIKE "%${keyword}%")`;
            }
            
            sql_list.push(queryPromise(sql_obj[i].table, sql));
        }
        for (var i = 0; i < sql_list.length; i++) {
            await sql_list[i];
        }
        let result_ = (await when(sql_list));
        let result = [];
        for(var i =0; i< result_.length;i++){
            result = [...result, ...(await result_[i])?.data ?? []];
        }
      
        result = await result.sort(function (a, b) {
            let x = a.date.toLowerCase();
            let y = b.date.toLowerCase();
            if (x > y) {
                return -1;
            }
            if (x < y) {
                return 1;
            }
            return 0;
        });
        let maxPage = makeMaxPage(result.length, page_cut);
        let result_obj = {};
        if(page){
            result = result.slice((page-1)*page_cut, (page)*page_cut)
            result_obj = { data: result, maxPage: maxPage };
        }else{
            result_obj = result;
        }
        return response(req, res, 100, "success", result_obj);
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
function getDateRangeData(param1, param2){  //param1은 시작일, param2는 종료일이다.
	var res_day = [];
 	var ss_day = new Date(param1);
   	var ee_day = new Date(param2); 
       var _mon_ = (ss_day.getMonth()+1); 
       var month =  _mon_ < 10 ? '0'+_mon_ : _mon_;	
  		while(ss_day.getTime() <= ee_day.getTime()){
  			var _mon_ = (ss_day.getMonth()+1);
  			_mon_ = _mon_ < 10 ? '0'+_mon_ : _mon_;
  			var _day_ = ss_day.getDate();
  			_day_ = _day_ < 10 ? '0'+_day_ : _day_;
            let current_flag = ss_day.getFullYear() + '-' + _mon_ + '-' +  _day_ <= returnMoment().substring(0, 10);
            if(month==_mon_ && current_flag){
                res_day.push(ss_day.getFullYear() + '-' + _mon_ + '-' +  _day_);
            }
   			ss_day.setDate(ss_day.getDate() + 1);
   	}
   	return res_day;
}
const getUserStatistics = async (req, res) => {
    try {
        let {page, page_cut, year, month, type} = req.query;
        if (!page_cut) {
            page_cut = 15;
        }
        let dates = [];
        let format = '';
        if(type=='month'){
            let last_month = 0;
            if(returnMoment().substring(0,4)==year){
                last_month = parseInt(returnMoment().substring(5,7));
            }else{
                last_month = 12;
            }
            for(var i=1;i<=last_month;i++){
                dates.push(`${year}-${i<10?`0${i}`:i}`);
            }
            format = '%Y-%m';
        }else{
            
            dates = getDateRangeData(new Date(`${year}-${month<10?`0${month}`:`${month}`}-01`),new Date(`${year}-${month<10?`0${month}`:`${month}`}-31`));
            format = '%Y-%m-%d';
        }
        dates = dates.reverse();
        let date_index_obj = {};
        for(var i =0;i<dates.length;i++){
            date_index_obj[dates[i]] = i;
        }
        let sql_list = [];
        let sql_obj = [
            {table:'user',date_colomn:'user_date',count_column:'user_count'},
            {table:'oneword',date_colomn:'post_date',count_column:'post_count'},
            {table:'oneevent',date_colomn:'post_date',count_column:'post_count'},
            {table:'theme',date_colomn:'post_date',count_column:'post_count'},
            {table:'strategy',date_colomn:'post_date',count_column:'post_count'},
            {table:'issue',date_colomn:'post_date',count_column:'post_count'},
            {table:'feature',date_colomn:'post_date',count_column:'post_count'},
            {table:'video',date_colomn:'post_date',count_column:'post_count'},
            {table:'notice',date_colomn:'post_date',count_column:'post_count'},
            {table:'comment',date_colomn:'comment_date',count_column:'comment_count'},
        ]
        let subStr = ``;
        if(type=='day'){
            subStr = ` WHERE SUBSTR(DATE, 1, 7)='${year+`-${month<10?`0${month}`:month}`}' `;
        }else if(type=='month'){
            subStr = ` WHERE SUBSTR(DATE, 1, 4)='${year}' `;
        }else{
            return response(req, res, -100, "fail", []) 
        }
        for (var i = 0; i < sql_obj.length; i++) {
            let sql = "";
            
            sql = `SELECT DATE_FORMAT(date, '${format}') AS ${sql_obj[i].date_colomn}, COUNT(DATE_FORMAT(date, '${format}')) AS ${sql_obj[i].count_column} FROM ${sql_obj[i].table}_table ${subStr} GROUP BY DATE_FORMAT(date, '${format}') ORDER BY ${sql_obj[i].date_colomn} DESC`;
            sql_list.push(queryPromise(sql_obj[i].table, sql));
        }
        for (var i = 0; i < sql_list.length; i++) {
            await sql_list[i];
        }
        let result = (await when(sql_list));
        let result_list = [];
        for(var i = 0;i<dates.length;i++){
            result_list.push({
                date:dates[i],
                user_count:0,
                visit_count:0,
                post_count:0,
                comment_count:0,
                views_count:0
            })
        }
        
        for(var i = 0;i<result.length;i++){
            let date_column = ``;
            let count_column = ``;
            if((await result[i])?.table=='user'){
                date_column = `user_date`;
                count_column = `user_count`;
            }else if((await result[i])?.table=='comment'){
                date_column = `comment_date`;
                count_column = `comment_count`;
            }else if((await result[i])?.table=='views'){
                date_column = `views_date`;
                count_column = `views_count`;
            }else if((await result[i])?.table=='visit'){
                date_column = `visit_date`;
                count_column = `visit_count`;
            }else{
                date_column = `post_date`;
                count_column = `post_count`;
            }
            let data_list = (await result[i])?.data;
            if(data_list.length>0){
                for(var j = 0 ; j< data_list.length ; j++ ){
                    result_list[date_index_obj[data_list[j][date_column]]][count_column] += data_list[j][count_column]
                }     
            }
           
        }
        let maxPage = makeMaxPage(result_list.length, page_cut);
        let result_obj = {};
        if(page){
            result_list = result_list.slice((page-1)*page_cut, (page)*page_cut)
            result_obj = { data: result_list, maxPage: maxPage };
        }else{
            result_obj = result_list;
        }
        return response(req, res, 100, "success", result_obj);
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getOneWord = (req, res) => {
    try {
        db.query("SELECT * FROM oneword_table ORDER BY sort DESC LIMIT 1", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getOneEvent = (req, res) => {
    try {
        db.query("SELECT * FROM oneevent_table ORDER BY sort DESC LIMIT 1", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getItems = (req, res) => {
    try {
        let { level, category_pk, status, user_pk, keyword, limit, page, page_cut, order } = req.query;
        let table = req.query.table ?? "user";
        let sql = `SELECT * FROM ${table}_table `;
        let pageSql = `SELECT COUNT(*) FROM ${table}_table `;

        let whereStr = " WHERE 1=1 ";
        if (level) {

            whereStr += ` AND user_level=${level} `;

        }
        if (category_pk) {
            whereStr += ` AND category_pk=${category_pk} `;
        }
        if (status) {
            whereStr += ` AND status=${status} `;
        }
        if (user_pk) {
            whereStr += ` AND user_pk=${user_pk} `;
        }
        if (keyword) {
            if (table == 'comment') {
                whereStr += ` AND (item_title LIKE '%${keyword}%' OR user_nickname LIKE '%${keyword}%' OR note LIKE '%${keyword}%') `;
            } else {
                whereStr += ` AND title LIKE '%${keyword}%' `;
            }
        }
        if (!page_cut) {
            page_cut = 15;
        }
        pageSql = pageSql + whereStr;
        sql = sql + whereStr + ` ORDER BY ${order ? order : 'sort'} DESC `;
        if (limit && !page) {
            sql += ` LIMIT ${limit} `;
        }
        if (page) {

            sql += ` LIMIT ${(page - 1) * page_cut}, ${page_cut}`;
            db.query(pageSql, async (err, result1) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    await db.query(sql, (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {
                            let maxPage = result1[0]['COUNT(*)'] % page_cut == 0 ? (result1[0]['COUNT(*)'] / page_cut) : ((result1[0]['COUNT(*)'] - result1[0]['COUNT(*)'] % page_cut) / page_cut + 1);
                            return response(req, res, 100, "success", { data: result2, maxPage: maxPage });
                        }
                    })
                }
            })
        } else {
            db.query(sql, (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", result)
                }
            })
        }
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getSetting = (req, res) => {
    try {
        db.query("SELECT * FROM setting_table ORDER BY pk DESC LIMIT 1", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const deleteItem = (req, res) => {
    try {
        let pk = req.body.pk ?? 0;
        let table = req.body.table ?? "";
        let sql = `DELETE FROM ${table}_table WHERE pk=? `
        db.query(sql, [pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addSetting = (req, res) => {
    try {
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        db.query("INSERT INTO setting_table (main_img) VALUES (?)", [image], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateSetting = (req, res) => {
    try {
        const pk = req.body.pk;
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        db.query("UPDATE setting_table SET main_img=? WHERE pk=?", [image, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateStatus = (req, res) => {
    try {
        const { table, pk, num } = req.body;
        db.query(`UPDATE ${table}_table SET status=? WHERE pk=? `, [num, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const onTheTopItem = (req, res) => {
    try {
        const { table, pk } = req.body;
        db.query(`SHOW TABLE STATUS LIKE '${table}_table' `, async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                let ai = result1[0].Auto_increment;
                await db.query(`UPDATE ${table}_table SET sort=? WHERE pk=? `, [ai, pk], async (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        await db.query(`ALTER TABLE ${table}_table AUTO_INCREMENT=?`, [ai + 1], (err, result3) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", [])
                            }
                        })
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const changeItemSequence = (req, res) => {
    try {
        const { pk, sort, table, change_pk, change_sort } = req.body;
        let date = new Date();
        date = parseInt(date.getTime() / 1000);

        let sql = `UPDATE ${table}_table SET sort=${change_sort} WHERE pk=?`;
        let settingSql = "";
        if (sort > change_sort) {
            settingSql = `UPDATE ${table}_table SET sort=sort+1 WHERE sort < ? AND sort >= ? AND pk!=? `;
        } else if (change_sort > sort) {
            settingSql = `UPDATE ${table}_table SET sort=sort-1 WHERE sort > ? AND sort <= ? AND pk!=? `;
        } else {
            return response(req, res, -100, "둘의 값이 같습니다.", [])
        }
        db.query(sql, [pk], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query(settingSql, [sort, change_sort, pk], async (err, result) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        return response(req, res, 100, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getCountNotReadNoti = async (req, res) => {
    try {
        const { pk, mac_adress } = req.body;
        let notice_ai = await getTableAI("notice").result - 1;
        let alarm_ai = await getTableAI("alarm").result - 1;
        let mac = mac_adress;
        if (!pk && !mac_adress) {
            mac = await new Promise((resolve, reject) => {
                macaddress.one(function (err, mac) {
                    if (err) {
                        console.log(err)
                        reject({
                            code: -200,
                            result: ""
                        })
                    }
                    else {
                        resolve({
                            code: 200,
                            result: mac
                        })
                    }
                })
            })
            mac = mac.result;
        }
        if (pk) {
            db.query("SELECT * FROM user_table WHERE pk=?", [pk], (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", { item: result[0], notice_ai: notice_ai, alarm_ai: alarm_ai })
                }
            })
        } else if (mac) {
            db.query("SELECT * FROM mac_check_noti_table WHERE mac_address=?", [mac], async (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    if (result.length > 0) {
                        return response(req, res, 100, "success", { mac: result[0], notice_ai: notice_ai, alarm_ai: alarm_ai })
                    } else {
                        await db.query("INSERT INTO mac_check_noti_table (mac_address) VALUES (?)", [mac], (err, result) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", { item: { mac_address: mac, last_alarm_pk: 0, last_notice_pk: 0 }, notice_ai: notice_ai, alarm_ai: alarm_ai })
                            }
                        })
                    }
                }
            })
        }

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const setCountNotReadNoti = async (req, res) => {
    try {
        const { table, pk, mac, category } = req.body;
        let notice_ai = await getTableAI("notice").result - 1;
        let alarm_ai = await getTableAI("alarm").result - 1;

        let key = pk || mac;
        db.query(`UPDATE ${table}_table SET last_${category}_pk=${category == 'notice' ? notice_ai : alarm_ai} WHERE ${pk ? 'pk' : 'mac_address'}=?`, [key], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", { item: { mac_address: mac, last_alarm_pk: 0, last_notice_pk: 0 }, notice_ai: notice_ai.result, alarm_ai: alarm_ai.result })
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
module.exports = {
    onLoginById, getUserToken, onLogout, checkExistId, checkExistNickname, sendSms, kakaoCallBack, editMyInfo, uploadProfile, onLoginBySns,//auth
    getUsers, getOneWord, getOneEvent, getItems, getItem, getHomeContent, getSetting, getVideoContent, getChannelList, getVideo, onSearchAllItem, findIdByPhone, findAuthByIdAndPhone, getComments, getCommentsManager, getCountNotReadNoti, getNoticeAndAlarmLastPk, getAllPosts, getUserStatistics,//select
    addMaster, onSignUp, addOneWord, addOneEvent, addItem, addIssueCategory, addNoteImage, addVideo, addSetting, addChannel, addFeatureCategory, addNotice, addComment, addAlarm,//insert 
    updateUser, updateItem, updateIssueCategory, updateVideo, updateMaster, updateSetting, updateStatus, updateChannel, updateFeatureCategory, updateNotice, onTheTopItem, changeItemSequence, changePassword, updateComment, updateAlarm,//update
    deleteItem, onResign,
};