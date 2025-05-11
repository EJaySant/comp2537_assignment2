require("./utils.js");
require('dotenv').config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const app = express();
const path = require("path");
const fs = require("fs");
const URL = require("url").URL;

const port = process.env.PORT || 8000;
const saltRounds = 12;
const expireTime = 60 * 60 * 1000;
const defaultUserType = "user";

// Secrets START
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
// Secrets END

var {database} = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
})

const membersMedia = [
    {fileName: "1364-dancing-toothless.gif", alt: "Dancing toothless meme"},
    {fileName: "BreadbugPikmin4.png", alt: "Breadbug from Pikmin 4"},
    {fileName: "HootySmugFace.png", alt: "Hooty from the Owl House with a smug face"}
];

app.locals.navLinks = {
    public: [{name: "Home", url: "/"}, {name: "404", url: "/404"}], 

    authenticated: [{name: "Members", url: "/members"}], 

    admin: [{name: "Admin", url: "/admin"}]
};

function formatList(arr) {
    if (arr.length === 0) return '';
    if (arr.length === 1) return arr[0];
    return arr.slice(0, -1).join(', ') + ' and ' + arr[arr.length - 1];
}

function isAuthenticated(req)
{
    if(req.session.authenticated)
    {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next)
{
    if (isAuthenticated(req)) 
    {
        next();
    }
    else 
    {
        res.redirect("/login");
    }
}

function isAdmin(req)
{
    if (req.session.user_type == "admin") 
    {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) 
{
    if (!isAdmin(req)) 
    {
        res.status(403);
        res.render("errorMessage", {errorMsg: "Not Authorized"});
        return;
    }
    else 
    {
        next();
    }
}

function storeHeaderVariables(req, res, next)
{
    app.locals.authenticated = req.session.authenticated;
    app.locals.user_type = req.session.user_type;

    let fullURL = req.protocol + "://" + req.get("host") + req.originalUrl;
    folders = new URL(fullURL).pathname.split("/").slice(1);
    app.locals.currentURL = "/" + folders[0];

    next();
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "app"));
app.use(express.urlencoded({extended: false}));

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use("/css", express.static(path.join(__dirname, "public", "css")));
app.use("/media", express.static(path.join(__dirname, "public", "media")));

app.use("/", storeHeaderVariables);
app.get("/", (req, res) => {
    res.render("index", {
        name: req.session.name, 
    });
});

app.use("/members", sessionValidation);
app.get("/members", (req, res) => {

    res.render("members", {name: req.session.name, membersMedia: membersMedia});
});

app.use("/admin", sessionValidation, adminAuthorization);
app.get("/admin", async (req, res) => {
    const users = await userCollection.find({}).toArray();

    res.render("admin", {users: users});
});

app.post("/changeUserType", async (req, res) => {
    let promoteValue = req.body.promote;
    let demoteValue = req.body.demote;
    let newUserType;

    const schema = Joi.object(
    {
        promoteValue: Joi.string().alphanum().max(20),
        demoteValue: Joi.string().alphanum().max(20)
    });

    const validationResult = schema.validate({promoteValue, demoteValue});
    if(validationResult.error != null)
    {
        res.redirect("errorMessage", {errorMsg: "Invalid name."});
        return;
    }

    if(promoteValue)
    {
        newUserType = "admin";
        await userCollection.updateOne({name: promoteValue}, {$set: {user_type: newUserType}});
    }
    else if(demoteValue)
    {
        newUserType = "user";
        await userCollection.updateOne({name: demoteValue}, {$set: {user_type: newUserType}});
    }
    else
    {
        res.redirect("errorMessage", {errorMsg: "Invalid action for changing user type."});
        return;
    }

    if(req.session.name == (promoteValue || demoteValue))
    {
        req.session.user_type = newUserType;
    }

    res.redirect("/admin");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.post("/signupSubmit", async (req, res) => {
    var name = req.body.name;
    var email = req.body.email
    var password = req.body.password;

    const schema = Joi.object(
    {
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({name, email, password});
    if(validationResult.error != null)
    {
        let missingFields = [];
        if(!name)
        {
            missingFields.push("name");
        }
        if(!email)
        {
            missingFields.push("email");
        }
        if(!password)
        {
            missingFields.push("password");
        }
        let signupFailMsg = `A valid ${formatList(missingFields)} is required.`;
        let route = "signup";
        res.render("authenticationFail", {failMsg: signupFailMsg, route: route});
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: defaultUserType});
    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = defaultUserType;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.post("/loginSubmit", async (req, res) => {
    let loginFailMsg = "Invalid email/password combination.";
    let route = "login";

    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required()
    });

	const validationResult = schema.validate({email, password});
	if(validationResult.error != null)
    {
		res.render("authenticationFail", {failMsg: loginFailMsg, route: route});
	    return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, user_type: 1, _id: 1}).toArray();

	if(result.length != 1) {
		res.render("authenticationFail", {failMsg: loginFailMsg, route: route});
		return;
	}

	if(await bcrypt.compare(password, result[0].password)) 
    {
		req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect("/members");
		return;
	}
	else 
    {
		res.render("authenticationFail", {failMsg: loginFailMsg, route: route});
		return;
	}
});

app.get("*dummy", (req, res) => {
    let errorMsg = "Page not found - 404";

    res.status(404);
    res.render("errorMessage", {errorMsg: errorMsg});
});

app.listen(port, () => {
    console.log('Server is running on https://localhost:' + port);
});