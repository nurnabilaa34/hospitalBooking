const mysql = require ("mysql");
const jwt = require ('jsonwebtoken');
const bcrypt = require ('bcryptjs');

const db = mysql.createConnection ({
    socketPath : process.env.DATABASE_SOCKETPATH,
    host: process.env.DATABASE_HOST,
    port: process.env.DATABASE_PORT,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

exports.login = async (req, res) => {
    try {
        const  {patientEmail, patientPassword} = req.body;

        if (!patientEmail || !patientPassword) {
            return res.status(400).render('login', {
                message: 'Please provide an email and password'
            }) 
        }

        db.query('SELECT * FROM patient WHERE patientEmail = ?', [patientEmail], async (error, results) => { 
            if(!results || !(await bcrypt.compare (patientPassword, results[0].patientPassword) )) {
                res.status(401).render('login', {
                    message: 'The email or password is incorrect'
                })
            } else {
                const id = results[0].id;

                const token = jwt.sign({id}, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN
                });

                console.log("The token is " +token);
                
                const cookiesOptions = {
                    expires: new Date(
                        Date.now() + process.env.JWT_COOKIES_EXPIRES * 24 *  60 * 60 * 1000
                    ),
                    httpOnly: true
                } 

                res.cookie ('jwt', token, cookiesOptions);
                res.status(200).redirect("/");
            }
        })

    } catch (error) {
        console.log(error);
    }
}

exports.register = (req, res) => {
    console.log (req.body);

    const {patientIC, patientName, patientEmail, patientPassword, passwordConfirm, patientPhoneNo} = req.body;

    db.query('SELECT patientEmail FROM patient WHERE patientEmail = ?', [patientEmail], async (error, results) => {
        if (error) {
            console.log(error);
        }

        if (results.length > 0) {
            return res.render('register', {
                message: 'That email is already in use'
            })
        } else if (patientPassword !== passwordConfirm) {
            return res.render('register', {
                message: 'The passwords do not match!'
            });
        }

        let hashedPassword = await bcrypt.hash (patientPassword, 8);
        console.log(hashedPassword);

        db.query('INSERT INTO patient SET ?', {patientIC: patientIC, patientName: patientName, patientEmail: patientEmail, 
            patientPassword: hashedPassword, patientPhoneNo: patientPhoneNo}, (error, result) => {
            if(error) {
                console.log(error);
            } else {
                return res.render('register', {
                    message: 'Successfully registered!'
                });
            }
        })
    }); 
}