require("./utils.js");
require('dotenv').config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const app = express();
const fs = require("fs");

const port = process.env.PORT || 8000;
const saltRounds = 12;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

function formatList(arr) {
    if (arr.length === 0) return '';
    if (arr.length === 1) return arr[0];
    return arr.slice(0, -1).join(', ') + ' and ' + arr[arr.length - 1];
}

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
})


app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use("/css", express.static("./public/css"));
app.use("/media", express.static("./public/media"));

app.get("/", (req, res) => {
    if(req.session.authorized)
    {
        let authorizedHomepageHTML = `
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Ervin Santiago&apos;s Assignment 1</title>
                    <link rel="stylesheet" href="css/styles.css">
                </head>
                <body>
                    <div>
                        <p>Hello, ${req.session.name}!</p>
                    </div>
                    <form action="/members" method="get">
                        <button>Go to Members Area</button>
                    </form>
                    <form method="get" action="/logout">
                        <button>Logout</button>
                    </form>
                </body>
            </html>
        `;
        res.send(authorizedHomepageHTML);
    }
    else
    {
        let mainDoc = fs.readFileSync("./app/index.html", "utf8");
        res.send(mainDoc);
    }
});

app.get("/members", (req, res) => {
    if(!req.session.authorized)
    {
        res.redirect("/");
    }
    else
    {
        let mediaFileNames = ["1364-dancing-toothless.gif", "Breadbug pikmin 4.png", "Hooty Smug Face.png"];
        let mediaFileAltMsg = ["Dancing toothless meme", "Breadbug from Pikmin 4", "Hooty smug face from The Owl House"];
        let randomNum = Math.floor(Math.random() * 3);

        let membersHTML = `
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Ervin Santiago&apos;s Assignment 1</title>
                    <link rel="stylesheet" href="css/styles.css">
                </head>
                <body>
                    <div>
                        <h1>Hello, ${req.session.name}!</h1>
                        <img src="media/${mediaFileNames[randomNum]}" alt="${mediaFileAltMsg[randomNum]}" width="500px" height="500px">
                    </div>
                    <form method="get" action="/logout">
                        <button>Logout</button>
                    </form>
                </body>
            </html>
        `;
        res.send(membersHTML);
    }
});

app.get("/signup", (req, res) => {
    let signupDoc = fs.readFileSync("./app/signup.html", "utf8");
    res.send(signupDoc);
});

app.get("/login", (req, res) => {
    let signupDoc = fs.readFileSync("./app/login.html", "utf8");
    res.send(signupDoc);
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
        let signUpFailHTML = `
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Ervin Santiago&apos;s Assignment 1</title>
                    <link rel="stylesheet" href="css/styles.css">
                </head>
                <body>
                    <div>
                        <p>A valid ${formatList(missingFields)} is required.</p>
                        <a href="/signup">Try again</a>
                    </div>
                </body>
            </html>
        `;
        res.send(signUpFailHTML);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
    req.session.authorized = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.post("/loginSubmit", async (req, res) => {
    let loginFailHTML = `
        <!DOCTYPE html>
        <html>
            <head>
                <title>Ervin Santiago&apos;s Assignment 1</title>
                <link rel="stylesheet" href="css/styles.css">
            </head>
            <body>
                <div>
                    <p>Invalid email/password combination.</p>
                    <a href="/login">Try again</a>
                </div>
            </body>
        </html>
    `;

    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required()
    });

	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
		res.send(loginFailHTML);
	    return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1}).toArray();

	if (result.length != 1) {
		res.send(loginFailHTML);
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authorized = true;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect("/members");
		return;
	}
	else {
		res.send(loginFailHTML);
		return;
	}
});

app.get("*dummy", (req, res) => {
    res.status = 404;
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log('Server is running on https://localhost:' + port);
});