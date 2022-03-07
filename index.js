var express = require('express');
var mysql = require('mysql');
var {json} = require('body-parser')
const util = require('util');
const { v4: uuidv4 } = require('uuid');
var app = express();

app.use(json())

var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "databasefood"
  });


con.connect()
const query = util.promisify(con.query).bind(con);


app.post("/sign-up" ,async function(req , res){
    let email = req.body.email;
    let phone =  req.body.phone;
    let add =  req.body.phone;
    try {
        const rowsEmail = await query(`SELECT COUNT(*) AS cnt FROM user WHERE email = '${email}'`)
        const rowsPhone = await query(`SELECT COUNT(*) AS cnt FROM user WHERE phone = '${email}'`)
        console.log(rowsEmail[0]['cnt'])
    } catch (error) {
        console.log(error)
    }
})

app.listen(3000,() => console.log("Server started"));