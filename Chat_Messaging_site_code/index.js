require("./utils.js");
const mysql = require("mysql2/promise")

require('dotenv').config();
const express = require('express');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const session = require('express-session');


const app = express();

const Joi = require("joi");

const port = process.env.PORT || 3000;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

var {database} = include('databaseConnection');


app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
	crypto: {
		secret: mongodb_session_secret
	}

})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

const isAuthenticated = (req, res, next) => {
    if (req.session.authenticated) {
        return res.redirect('/loggedin');
    }
    return next();
};

const sqldb = process.env.SQL_DATABASE;
const sqluser = process.env.SQL_USER;
const sqlpassword = process.env.SQL_PASSWORD;
const sqlhost = process.env.SQL_HOST;

const sqlConfig = {
    host: process.env.SQL_HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASSWORD,
    database: process.env.SQL_DATABASE,
    multipleStatements: true
};

async function connectAndQuery() {
    try {
        // Create a connection to the database
        const connection = await mysql.createConnection({
            host: sqlhost, // MySQL server host
            user: sqluser, // MySQL username
            password: sqlpassword, // MySQL password
            database: sqldb, // MySQL database name
            multipleStatements: true // Allow multiple SQL statements per query
        });

        // Perform a query
        const [rows, fields] = await connection.execute('SELECT * FROM users');

        // Log query results
        console.log(rows);

        // Close the connection
        await connection.end();
    } catch (error) {
        console.error('Error connecting to the database:', error);
    }
}


const userCollection = database.db(sqldb).collection('users');

// Call the function
connectAndQuery();

app.get('/', isAuthenticated, (req,res) => {

    var html = `
    <h2><a href="/createUser">Sign Up</a></br>
    <a href="/login">Log In</a><h2>
    `

    res.send(html);
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, user_id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/createUser', (req,res) => {
    var html = `
    <h2>Create user</h2>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req,res) => {

    var html = `
    <h2>Log in</h2>
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/loginErrorUser', (req,res) => {
    var html = `
    <h2>Log in</h2>
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    <h3 style='color:darkred;'>User not found</h3>
    `;
    res.send(html);
});

app.get('/loginErrorPassword', (req,res) => {
    var html = `
    <h2>Log in</h2>
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    <h3 style='color:darkred;'>Incorrect Password</h3>
    `;
    res.send(html);
});


app.post('/submitUser', async (req, res) => {
    const { username, password } = req.body;

    // Validation schema for user input
    const schema = Joi.object({
        username: Joi.string().alphanum().required(),
        password: Joi.string().min(5).required() // Ensure strong password requirements
    });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error) {
        console.log(validationResult.error);
        return res.redirect("/createUser");
    }

    try {
        // Hash the user's password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Connect to the MySQL database
        const connection = await mysql.createConnection(sqlConfig);

        // Insert the new user into the database using a parameterized query
        const insertQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
        const [rows] = await connection.execute(insertQuery, [username, hashedPassword]);

        console.log("Inserted user:", rows);
        await connection.end();

        // Set session variables and redirect the user
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/loggedin');
    } catch (error) {
        console.error('Error inserting user into MySQL database:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/loggingin', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const schema = Joi.string().required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    try {
        const connection = await mysql.createConnection(sqlConfig);
        
        // Use a prepared statement to prevent SQL injection
        const safeQuery = 'SELECT * FROM users WHERE username = ?'; // Placeholder for username
        console.log("safeQuery: ", safeQuery);
        const [users] = await connection.execute(safeQuery, [username]); // Provide username as a parameter

        await connection.end();

        if (users.length === 0) {
            console.log("user not found");
            res.redirect("/loginErrorUser");
            return;
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            console.log("correct password");
            req.session.authenticated = true;
            req.session.username = username;
            req.session.cookie.maxAge = expireTime;
            res.redirect('/loggedin');
        } else {
            console.log("incorrect password");
            res.redirect("/loginErrorPassword");
        }
    } catch (error) {
        console.error('Error checking user in MySQL database:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var username = req.session.username;

    var RE = Math.floor(Math.random() * 3);

    var html = `
    <h2>Successfully logged in
    ` ;

    var html2 = `
    <h2><a href="/logout">Log Out</a></h2>    
    `

    if (RE == 0) {
        res.send(html + username + "!</h2>" + "</br><img src='/RE1.jpg' style='width:250px;'></br>" + html2);
    }
    else if (RE == 1) {
        res.send(html + username + "!</h2>" + "<img src='/RE2.png' style='width:250px;'></br>" + html2);
    } 
    else if (RE == 2) {
        res.send(html + username + "!</h2>" + "<img src='/RE3.jpg' style='width:250px;'></br>" + html2);
    }
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/email', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("The email you input is: "+email);
    }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.get('/RE/:id', (req,res) => {

    var RE = req.params.id;

    if (RE == 1) {
        res.send("RE1: <img src='/RE1.jpg' style='width:250px;'>");
    }
    else if (RE == 2) {
        res.send("RE2: <img src='/RE2.png' style='width:250px;'>");
    } 
    else if (RE == 3) {
        res.send("RE3: <img src='/RE3.jpg' style='width:250px;'>");
    }
    else {
        res.send("Invalid Resident evil game id: "+RE);
    }
});

app.use(express.static(__dirname + "/public"));

app.use((req, res, next) => {
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
});

app.use((err, req, res, next) => {
    const status = err.status || 500;

    res.status(status).send(`Error ${status}: ${err.message}`);
});

app.listen(port, () => {
    console.log("Your Assignment 1 is listening on port "+port);
})
