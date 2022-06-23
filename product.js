const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://phatpham0209:Lovely94@databaseproduct.fgct2.mongodb.net/?retryWrites=true&w=majority');
// viết schema
const productSchema = new mongoose.Schema({
    name: { type: String, require: true, unique: true },
    address: { type: String, require: true,  default: ''},
    price: { type: Number, default: 0 },
    img: { type: String, default: '' },
    quantity: {type:Number, default: 0},
    gallery: { type: Array, default: [] },
    date_created: { type: Date, default: Date.now() },
    date_updated: { type: Date, default: null }
})

module.exports = mongoose.model('Product', productSchema);

// phân tích product

// 1. name
// 2. slug
// 3. parent
// 4. id_user
// 5. price
// 6. img
// 7. gallery
// 5. status
// 6. trash
// 7. date_created
// 8. date_updated