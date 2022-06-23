const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const {json} = require('body-parser');


const User = require("./user")
const Token = require("./token")
const Product = require("./product")
const Order = require("./order")



const app = express();

app.use(json())
app.use("/assets",express.static("assets"))
const secret = "Ứng dụng cá nhân";
 
//register

app.post("/user/sign-up", function(req, res){
    // Cho user đăng kí thành viên mới
    // Paramsters: Email, Password, Name, Adress, Phone
    // Response:    {"result":1, "errMsg":"Thành công"}  
    //              {"result":0, "errMsg":"Email bị trùng"}
    //              {"result":0, "errMsg":"Không gửi mail active"}
    var {email , password , name , address , phone} = req.body
    if(email == null || password == null || name ==null || address ==null || phone ==null){
        res.status(404).json({"result":0, "message":"Missing Parameters"}).end();
        
    }else{
        const emailRegexp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const passwordLength = 8
        const phoneLength = 10
        if(!emailRegexp.test(email)){
            res.status(404).json({"result":0, "message":"Invalid email"}).end();
        }else if(password.length < passwordLength){
            res.status(404).json({"result":0, "message":"Password must be at least 8 characters"}).end();
        }else if(phone.length < phoneLength){
            res.status(404).json({"result":0, "message":"Phone must be at least 10 number"}).end();
        }else if(name.length < 1){
            res.status(404).json({"result":0, "message":"Name is empty"}).end();
        }else{
            User.findOne({email}, function(err, user){
                if(err){
                    res.status(500).json({"result":0, "message":"Mongo Server Error!"}).end();
                }else{
                    if(!user){
                        bcrypt.genSalt(10, function(err2, salt) {
                            if(err2){
                                res.status(500).json({"result":0, "message":"Gen Salt Error"}).end();
                            }else{
                                bcrypt.hash(password, salt, function(err3, hash) {
                                    if(err3){
                                        res.status(500).json({"result":0, "message":"Password Hash Error"}).end();
                                    }else{
                                        var newUser = new User({
                                            email        :   email,
                                            password     :   hash,
                                            name         :   name,
                                            adress       :   address,
                                            phone        :   phone,
                                            registerDate :   Date.now(),
                                            userGroup    :   0,          // 1 Admin, 0 Khách thường
                                        })

                                        newUser.save(function(err){
                                            if(err){
                                                res.status(500).json({"result":0, "message":"Save new User Error"})
                                            }else{
                                                res.json({
                                                    "result":1, 
                                                    "message":"Create User Success" ,
                                                    "data" : {
                                                        "email" : newUser['email'],
                                                        "name" : newUser['name'],
                                                        "phone" : newUser['phone'],
                                                        "userGroup" : newUser['userGroup'],
                                                        "registerDate" : newUser['registerDate'],
                                                    }}).end();
                                            }
                                        });
                                    }
                                });
                            }
                        });

                    }else{
                        res.status(404).json({"result":0, "message":"Email already exists"}).end();
                    }
                }
            });
        }
    }
    
});

// login
app.post("/user/sign-in",async function(req, res){
    var {email , password } = req.body
    if(!email || !password){
        res.status(404).json({"result":0, "message": "Email or Password is empty"}).end();
    }else{
        User.findOne({email}, function(err, item){ // CHƯA BỎ PASSWORD NHA
            if(err || !item){
                res.status(500).json({"result":0, "message":"Email is not exists"}).end();
            }else{
                bcrypt.compare( password ,item.password, function(err, resB) {
                    if(err || resB === false){
                        res.status(500).json({"result":0, "message":"Password is error"}).end();
                    }else{
                        Token.findOne({user : item._id}, function(err , responseToken){
                            if(err){
                                res.status(500).json({"result":0, "message":err}).end();
                            }
                            if(!responseToken){
                                var objectToken = {
                                    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 60 * 60 * 60),
                                    data: item
                                }
                                var token = jwt.sign(objectToken, secret)  
                                var newToken = new Token({
                                    token:token,
                                    user:item._id,
                                    dateCreated:Date.now()
                                });
                                newToken.save(function(err){
                                    if(err){
                                        return res.status(500).json({"result":0, "message": "Save token is error"}).end();
                                    }else{
                                        return res.json({
                                            "result":1,
                                            "data": {
                                                "email" : item['email'],
                                                "name" : item['name'],
                                                "phone" : item['phone'],
                                                "userGroup" : item['userGroup'],
                                                "registerDate" : item['registerDate'],
                                                "token" : token
                                            },
                                            "message": "Đăng nhập thành công."
                                        }).end()
                                    }
                                });
                            } else {
                                return res.json({
                                    "result":1,
                                    "data": {
                                        "email" : item['email'],
                                        "name" : item['name'],
                                        "phone" : item['phone'],
                                        "userGroup" : item['userGroup'],
                                        "registerDate" : item['registerDate'],
                                        "token" : responseToken.token
                                    },
                                    "message": "Đăng nhập thành công."
                                }).end()
                            }
                        })
                    }
                });
            }
        });
    }
});

app.post('/user/refreshtoken' , function(req, res) {
    var {email , password } = req.body
    if(!email || !password){
        res.status(404).json({"result":0, "message": "Email or Password is empty"}).end();
    }else{
        User.findOne({email}, function(err, item){ // CHƯA BỎ PASSWORD NHA
            if(err || !item){
                res.status(500).json({"result":0, "message":"Email is not exists"}).end();
            }else{
                bcrypt.compare( password ,item.password, function(err, resB) {
                    if(err || resB === false){
                        res.status(500).json({"result":0, "message":"Password is error"}).end();
                    }else{
                        var objectToken = {
                            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 60 * 60 * 60),
                            data: item
                        }
                        var token = jwt.sign(objectToken, secret)  
                        var newToken = new Token({
                            token:token,
                            user:item._id,
                            dateCreated:Date.now()
                        });
                        Token.findOneAndUpdate({user : item._id}, {$set:{token: newToken.token, dateCreated: newToken.dateCreated}}, function(err , responseToken){
                            if(err){
                               return res.status(500).json({"result":0, "message":err}).end();
                            }
                            return res.json({
                                "result":1,
                                "data": {
                                    "token" : responseToken.token
                                },
                                "message": "Cập nhật token thành công"
                            }).end()
                        })
                    }
                });
            }
        });
    }
})

// list product
app.get('/product', (req, res) => {
    Product.find({}, (err, data)=>{
        if(err){
            res.status(500).json({"result":0, "message": "Erro database"}).end();
        }else{
            if(data==''){
                res.json({"result":0, "data":[]}).end();
            }else{
                res.json({"result":1, "data": data}).end();
            }
        }
    })
})

// create cart
app.post('/order/add-to-cart',  (req, res) => {
    const {id_product} = req.body
    jwt.verify(extractToken(req), secret, function(err, decoded) {
        if(err){
            return res.status(500).send({"result" : 0 , "message" : err.message}).end()
        }
        const {_id} = decoded.data
        Order.findOne({id_user : _id , status : false}, (err, data)=>{
            if(err){
                return res.status(500).json({"result":0, "message": err.message}).end();
            }else{
                Product.findOne({_id : id_product} ,async function(err , obj){
                    if(err){
                        res.status(500).json({"result" : 0 , "message" : err.message}).end();
                    }else{
                        if(!obj){
                            res.status(500).json({"result" : 0 , "message" : "Product is empty"}).end();
                        }else{
                            if(data == null){
                                // thêm
                                const products = [{...obj._doc,quantity : 1}]
                                const newOrder = new Order({ id_user : _id,products, price : obj.price})
                                newOrder.save(function(err , dataOrder){
                                    if(err){
                                        res.status(500).json({"result":0, "message": err.message}).end();
                                    }else{
                                        res.json({"result":1, "data": dataOrder}).end();
                                    }
                                })
                            }else{
                                // Lấy ra thông tin sản phẩm này
                                Order.findOne({id_user : _id} , function(err , order){
                                    if(err){
                                        res.status(500).json({"result" : 0 , "message" : err.message}).end();
                                    }else{
                                        if(order == null){
                                            res.status(500).json({"result" : 0 , "message" : "Order is empty"}).end();
                                        }else{
                                            const index = order.products.findIndex((element) => element._id.toString() == obj._id.toString());
                                            if(index >= 0){
                                                const products = order.products.map(item => {
                                                    if(item._id == id_product){
                                                        return {...item , quantity : item.quantity + 1}
                                                    }
                                                    return item
                                                })
                                                const totalPrice = products.reduce((total , current) =>{
                                                    return total + current.price * current.quantity;
                                                },0);
                                                Order.findOneAndUpdate({id_user : _id},{products,price: totalPrice} , {new : true} , function(err,newOrder){
                                                    if(err){
                                                        res.status(500).json({"result":0, "message": err.message}).end();
                                                    }else{
                                                        res.json({"result":1, "data": newOrder}).end();
                                                    }
                                                })
                                            }else{
                                                const newProduct = {...obj._doc,quantity : 1}
                                                const products = Object.assign([],order.products)
                                                products.push(newProduct)
                                                const totalPrice = products.reduce((total , current) =>{
                                                    return total + current.price * current.quantity;
                                                },0);
                                                Order.findOneAndUpdate({id_user : _id},{products,price: totalPrice} , {new : true} , function(err,newOrder){
                                                    if(err){
                                                        res.status(500).json({"result":0, "message": err.message}).end();
                                                    }else{
                                                        res.json({"result":1, "data": newOrder}).end();
                                                    }
                                                })
                                            }
                                        
                                        }
                                    }
                                })
                            }
                        }
                    }
                })
            }
        })
    });

   
})

// giỏ hàng 
app.post('/order', (req, res) => {

    jwt.verify(extractToken(req), secret, function(err, decoded) {
        if(err){
            return res.status(500).send({"result" : 0 , "message" : err.message}).end()
        }
        const {_id} = decoded.data
        const id_user = _id
        const id_order = req.body.id_order
        Order.findOne({id_user,_id : id_order,status : false,}, (err, data)=>{
            if(err){
                res.status(500).json({"result":0, "data": "Order is error"});
            }else{
                if(data==null){
                    res.status(500).json({"result":0, "data": "Order is error"});
                }else{
                    res.json({"result":1, "data": data});
                }
            }
        })
    })
})

//cập nhật giỏ hàng
app.post('/order/update', function (req, res) {
    const {id_product,id_order,quantity} = req.body
    jwt.verify(extractToken(req), secret, function(err, decoded) {
        if(err){
            return res.status(500).send({"result" : 0 , "message" : err.message}).end()
        }
        const {_id} = decoded.data
        Order.findOne({id_user : _id , _id : id_order, status : false}, (err, order)=>{
            if(err){
                return res.status(500).json({"result":0, "message": err.message}).end();
            }else{
               if(order == null){
                return res.status(500).json({"result":0, "message": "Order is error"}).end();
               }
               Product.findOne({_id : id_product} ,async function(err , obj){
                if(err){
                    res.status(500).json({"result" : 0 , "message" : "Product is error"}).end();
                }else{
                    if(!obj){
                        res.status(500).json({"result" : 0 , "message" : "Product is empty"}).end();
                    }else{
                        let products = []
                        if(quantity <= 0){
                            products = order.products.filter(item => {
                                if(item._id == id_product){
                                    return false
                                }
                                return true
                            }) 
                        }else{
                            products = order.products.map(item => {
                                if(item._id == id_product){
                                    return {...item , quantity}
                                }
                                return item
                            }) 
                        }
                         
                        const totalPrice = products.reduce((total , current) =>{
                            return total + current.price * current.quantity;
                        },0);
                        Order.findOneAndUpdate({id_user : _id},{products,price: totalPrice} , {new : true} , function(err,newOrder){
                            if(err){
                                res.status(500).json({"result":0, "message": err.message}).end();
                            }else{
                                res.json({"result":1, "data": newOrder}).end();
                            }
                        })
                    }
                }
            })
               
            }
        })
    });
}) 

// lịch sử giỏ hàng của người dùng
app.get('/order/history', (req, res) => {
    jwt.verify(extractToken(req), secret, function(err, decoded) {
        if(err){
            return res.status(500).send({"result" : 0 , "message" : err.message}).end()
        }
        const {_id} = decoded.data
        const id_user = _id
        Order.find({id_user , status : true}, (err, data)=>{
            if(err){
                res.status(500).json({"result":0, "data": "Order is error"});
            }else{
                if(data==null){
                    res.json({"result":0, "data": "Không có sản phẩm nào."});
                }else{
                    res.json({"result":1, "data": data});
                }
            }
        })
    })
})

// confirm giỏ hàng
app.post('/order/confirm', (req, res) => {
    const{id_order , status} = req.body;
    jwt.verify(extractToken(req), secret, function(err, decoded) {
        if(err){
            return res.status(500).send({"result" : 0 , "message" : err.message}).end()
        }
        const {_id} = decoded.data
        const id_user = _id
        Order.findOne({id_user,_id : id_order,status : false}, (err, data)=>{
            if(err){
                res.status(500).json({"result":0, "data": "Lỗi database."});
            }else{
                if(data == null){
                    res.status(500).json({"result":0, "data": "Order is error"});
                }else{
                    Order.findOneAndUpdate({id_user,_id : id_order,status : false},{status} , {new : true} , function(err,newOrder){
                        if(err){
                            res.status(500).json({"result":0, "message": err.message}).end();
                        }else{
                            res.json({"result":1, "data": "Order confirm success"}).end();
                        }
                    })
                }
            }
        })
    })
})


//insert new product
app.post('/insert/product',  (req, res) => {

    const arrProduct = [
        new Product({
            name: "A Chảy - Mì Sủi Cảo & Cơm Chiên Gà Xối Mỡ - Shop Online",
            address : "58/11 Nguyễn Văn Săng, P. Tân Sơn Nhì, Tân Phú, TP. HCM",
            price : 30000,
            img : "assets/\images/\achay/\banner.jpg",
            gallery: [
                "assets/\images/\achay/\img1.jpg",
                "assets/\images/\achay/\img2.jpg",
                "assets/\images/\achay/\img3.jpg",
            ]
        }),
        new Product({
            name: "Anh Quán - Mì Khô Gà Quay & Hủ Tiếu Mì Sủi Cảo",
            address : "80/17/138 Dương Quảng Hàm, P. 5, Gò Vấp, TP. HCM",
            price : 40000,
            img : "assets/\images/\anhquan/\banner.jpg",
            gallery: [
                "assets/\images/\anhquan/\img1.jpg",
                "assets/\images/\anhquan/\img2.jpg",
                "assets/\images/\anhquan/\img3.jpg",
            ]
        }),
        new Product({
            name: "Tiệm NoanNoan SeaFood - Tân Kỳ Tân Quý",
            address : "295 Tân Kỳ Tân Quý, P. Tân Sơn Nhì, Tân Phú, TP. HCM",
            price :100000,
            img : "assets/\images/\bachtuot/\banner.jpg",
            gallery: [
                "assets/\images/\bachtuot/\img1.jpeg",
                "assets/\images/\bachtuot/\img2.jpeg",
                "assets/\images/\bachtuot/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Xôi Chiên - Hẻm 50 Phùng Văn Cung",
            address : "50/22/4 Phùng Văn Cung, P. 7, Phú Nhuận, TP. HCM",
            price : 10000,
            img : "assets/\images/\banhchien/\banner.jpg",
            gallery: [
                "assets/\images/\banhchien/\img1.jpg",
                "assets/\images/\banhchien/\img2.jpg",
                "assets/\images/\banhchien/\img3.jpg",
            ]
        }),
        new Product({
            name: "Bánh Mì Má Hải - Vĩnh Viễn",
            address : "187 Vĩnh Viễn, P. 4, Quận 10, TP. HCM",
            price : 15000,
            img : "assets/\images/\banhmymahai/\banner.jpg",
            gallery: [
                "assets/\images/\banhmymahai/\img1.jpeg",
                "assets/\images/\banhmymahai/\img2.jpeg",
                "assets/\images/\banhmymahai/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Bún Bò Huế 14B",
            address : "14B Đường Số 46, P. 5, Quận 4, TP. HCM",
            price : 50000,
            img : "assets/\images/\bunbo/\banner.jpg",
            gallery: [
                "assets/\images/\bunbo/\img1.jpeg",
                "assets/\images/\bunbo/\img2.jpeg",
                "assets/\images/\bunbo/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Bún Đậu Mạc Văn Khoa - Vĩnh KhánhB",
            address : "122 Vĩnh Khánh, Phường 8, Quận 4, TP. HCM",
            price : 45000,
            img : "assets/\images/\bundau/\banner.jpg",
            gallery: [
                "assets/\images/\bundau/\img1.jpeg",
                "assets/\images/\bundau/\img2.jpeg",
                "assets/\images/\bundau/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Gỏi Cuốn Cô Loan",
            address : "57/3 Đội Cung, P. 11, Quận 11, TP. HCM",
            price : 7000,
            img : "assets/\images/\goicuon/\banner.jpg",
            gallery: [
                "assets/\images/\goicuon/\img1.jpeg",
                "assets/\images/\goicuon/\img2.jpeg",
                "assets/\images/\goicuon/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Hapi - Hamburger Bò Teriyaki - Điện Biên Phủ",
            address : "625 Điện Biên Phủ, P. 25, Bình Thạnh, TP. HCM",
            price : 10000,
            img : "assets/\images/\hapi/\banner.jpeg",
            gallery: [
                "assets/\images/\hapi/\img1.jpeg",
                "assets/\images/\hapi/\img2.jpeg",
                "assets/\images/\hapi/\img3.jpeg",
            ]
        }),
        new Product({
            name: "Tocotoco Bubble Tea",
            address : "657 Tỉnh Lộ 10, P. Bình Trị Đông B, Bình Tân, TP. HCM",
            price : 50000,
            img : "assets/\images/\tocotoco/\banner.jpg",
            gallery: [
                "assets/\images/\tocotoco/\img1.jpeg",
                "assets/\images/\tocotoco/\img2.jpeg",
                "assets/\images/\tocotoco/\img3.jpeg",
            ]
        }),
    ]
    Product.insertMany(arrProduct)
})

function extractToken(req){
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
        return req.query.token;
    }
    return null;
}

app.listen(process.env.PORT || 3001,() => console.log("Server started"));


