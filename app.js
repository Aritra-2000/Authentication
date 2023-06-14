//jshint esversion:6

require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require('passport-facebook');
const GitHubStrategy = require('passport-github').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//level-4
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

//level-3
// const md5 = require("md5");

//level-2
//const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://Aritra:Test123@cluster0.nxosm3a.mongodb.net/userDB", {useNewUrlParser: true});


const userSchema = new Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//level-2
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3011/auth/google/secrets",
    useprofileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3011/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3011/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/facebook",
  passport.authenticate("facebook")
);

app.get("/auth/github",
  passport.authenticate("github")
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/auth/github/secrets",
  passport.authenticate('github', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {

  User.find({"secret": { $ne: null }}).then(function(foundUsers){
       if(foundUsers){
         res.render("secrets", {usersWithSecrets: foundUsers});
       }
     }).catch(function(err){
       console.log(err);
     });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
      res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id).then(function(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save().then(function(){
          res.redirect("/secrets");
        });
  }).catch(err => {
    console.log(err);
  });
});

app.get("/logout", function (req, res , next) {
  req.logout( function(err){
    if(err){
      return next(err);
    }
    res.redirect("/");
  });
})


app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user) {
      if(err){
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
  });


  //upto level-4
  // bcrypt.hash(req.body.password, saltRounds).then(function(hash) {
  //
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save().then(function(){
  //     res.render("secrets");
  //   }).catch(function (err) {
  //     console.log(err);
  //   });
  // }).catch(function (err) {
  //   console.log(err);
  // })

});


app.post("/login", function(req, res){

 const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  })

  //upto level-4
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username}).then(function (foundUser) {
  //   if(foundUser){
  //     bcrypt.compare(password, foundUser.password).then(function(result) {
  //         if(result === true) {
  //             res.render("secrets");
  //         }
  //     });
  //   }
  // }).catch(function (err) {
  //   console.log(err);
  // });

});


app.listen(process.env.PORT || 3011, function(req, res){
  console.log("Server running on port 3011.");
})
