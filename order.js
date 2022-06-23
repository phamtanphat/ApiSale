const mongoose = require("mongoose");
mongoose.connect('mongodb+srv://phatpham0209:Lovely94@databaseproduct.fgct2.mongodb.net/?retryWrites=true&w=majority');
const orderSchema = new mongoose.Schema({
    products: {type:Array, default: []},
    id_user: {type:mongoose.SchemaTypes.ObjectId, default: null},
    price: {type:Number, default: 0},
    status: {type: Boolean, default: false},
    date_created: { type: Date, default: Date.now() },
});

module.exports = mongoose.model("Order", orderSchema)