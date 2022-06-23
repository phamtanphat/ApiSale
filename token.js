const mongoose = require("mongoose");
mongoose.connect('mongodb+srv://phatpham0209:Lovely94@databaseproduct.fgct2.mongodb.net/?retryWrites=true&w=majority');
const tokenSchema = new mongoose.Schema({
    token: String,
    user:mongoose.SchemaTypes.ObjectId,
    dateCreated:Date
});

module.exports = mongoose.model("Token", tokenSchema)