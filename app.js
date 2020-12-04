require('dotenv').config();
const express=require('express');
const app=express();
const bodyParser=require('body-parser');
const mongoose=require('mongoose');
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const FacebookStrategy=require('passport-facebook').Strategy;
const findOrCreate=require('mongoose-findorcreate');
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect('mongodb://localhost:27017/userDB',{useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex',true);
const userSchema=new mongoose.Schema({
  email: String,
  username:{
    type: String,
    sparse: true,
    unique: true
  },
  password:{
    type: String,
    sparse: true,
    unique: true
  },
  googleId: String,
  facebookId: String,
  secrets: [{type: String}]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User=mongoose.model("User",userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/login");
});
app.get("/secrets",function(req,res){
  if(req.isAuthenticated())
    res.render("secrets",{secrets: req.user.secrets});
    else
    res.redirect("/login");
});
app.post("/register",function(req,res){
    User.register({username: req.body.username},req.body.password,function(err,user){
      if(err)
      {
        console.log(err);
        res.redirect("/register");
      }
      else
      {
        passport.authenticate('local')(req,res,function(){
          res.redirect("/secrets");
        });
      }
    });
});
app.post("/login",function(req,res){
    const user=new User({
      username: req.body.username,
      password: req.body.password
    });
    req.login(user,function(err){
      if(err)
      res.send(err);
      else
      {
        passport.authenticate('local')(req,res,function(){
          res.redirect("/secrets");
        });
      }
    });
});
app.get("/",function(req,res){
  res.render("home");
});
app.get("/register",function(req,res){
  res.render("register");
});
app.get("/login",function(req,res){
  res.render("login");
});
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
    passport.authenticate('facebook'));
    app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });
  app.get('/submit',function(req,res){
    if(req.isAuthenticated())
    res.render('submit');
    else
    res.redirect("/login");
  });
  app.post('/submit',function(req,res){
    if(req.isAuthenticated())
    {
      User.updateOne({_id: req.user._id},{$push: {secrets: req.body.secret}},function(err){
        if(err)
        console.log(err);
        else
        res.redirect("/secrets");
      });
    }
    else
    res.redirect('/login');
  });
  app.get('/everysecret',function(req,res){
    if(req.isAuthenticated()){
      let array = [];
      User.find({secrets: {$exists: true}},function(err,users){
        if(err)
        console.log(err);
        else
        {
          users.forEach(function(user){
            (user.secrets).forEach(function(secret){
                array.push(secret);
            });
          });
          res.render('secrets',{secrets: array});
        }
      });
    }
    else
    res.redirect('/login');
  });
app.listen(process.env.PORT || 3000,function(){
  console.log("Server running");
});
