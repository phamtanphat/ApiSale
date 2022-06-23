const mongoose = require("mongoose");
mongoose.connect('mongodb+srv://phatpham0209:Lovely94@databaseproduct.fgct2.mongodb.net/?retryWrites=true&w=majority');
const userSchema = new mongoose.Schema({
    email: String,
    password: String,   
    name:String,
    address:String,
    phone:String,
    userGroup: Number,   // 1:Admin, 0 Khách hàng
    registerDate:Date,

});
module.exports = mongoose.model("User", userSchema);