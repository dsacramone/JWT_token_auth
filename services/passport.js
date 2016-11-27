const passport = require('passport');
const User = require('../models/users');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

// lets use a local strategy for email/pw
// local strategy assumes username, but we email, lets map it.
const localOptions = {usernameField: 'email'}
const LocalStrategy = require('passport-local')

const localLogin = new LocalStrategy(localOptions, function(email, password, done){
	//verify this username(email) and password, call done of correct
	User.findOne({email: email}, function(err, user) {
		if(err) return done(err)

		if(!user) return done(null, false)

		// returns a user
		// compare passwords
		// password equal to user.password - but we hashed / salted it.
		// lets decode our stored password
		user.comparePassword(password, function(err, isMatch){
			if (err) return done(err)
			if(!isMatch) return done(null, false)

			return done(null, user)
		})

	});
})


// setup options for jwt strategy
const jwtOptions = {
	// look in the header at the key authorization
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret
}

// create jwt strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
	// see if the user.id in the payload exists in our database
	// if it does call done(user)
	// otherwise, call done w/o user done()
	User.findById(payload.sub, function(error, user) {
		if(error) return done(err, false);

		if(user) {
			done(null, user)
		} else {
			done(null, false)
		}
	})
})

// tell passport to use this strategy
passport.use(jwtLogin); // pass in the strategy we created
passport.use(localLogin);