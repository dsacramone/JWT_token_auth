// our user schema for mongoose

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our Model
const userSchema = new Schema({
	// only one user can be created with this. Make sure to use lowercase, not case sensitive.
	email: { type: String, unique: true, lowercase: true},
	password: String
})

// on save hook, encrypt password
userSchema.pre('save', function(next){
	const user = this;
	bcrypt.genSalt(10, function(error, salt) {
		if(error) return next(error);

		bcrypt.hash(user.password, salt, null, function(error, hash) {
			if(error) return next(error);

			user.password = hash;
			next();
		})
	})
})

userSchema.methods.comparePassword = (candidatePW, callback) => {
	bcrypt.compare(candidatePW, this.password, (err, isMatch) => {
		if(err) return callback(err)
		callback(null, isMatch)
	})
}

// create the model class, a class of users
const ModelClass = mongoose.model('user', userSchema);

//export the mode
module.exports = ModelClass;