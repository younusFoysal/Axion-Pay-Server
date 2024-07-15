const express = require('express');
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000;

const corsOptions = {
    origin: [
        'http://localhost:5173',
        'http://localhost:5174'
    ],
    credentials: true,
    optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const verifyToken = async (req, res, next) => {
    const token = req.cookies?.token;
    console.log(token);
    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            console.log(err);
            return res.status(401).send({ message: 'unauthorized access' });
        }
        req.user = decoded;
        next();
    });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.q3baw43.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    try {
        const db = client.db('axionpayDB');
        const usersCollection = db.collection('users');

        const verifyAdmin = async (req, res, next) => {
            const user = req.user;
            const query = { email: user?.email };
            const result = await usersCollection.findOne(query);
            console.log(result?.role);
            if (!result || result?.role !== 'admin')
                return res.status(401).send({ message: 'unauthorized access!!' });
            next();
        };

        const verifyHost = async (req, res, next) => {
            const user = req.user;
            const query = { email: user?.email };
            const result = await usersCollection.findOne(query);
            console.log(result?.role);
            if (!result || result?.role !== 'host') {
                return res.status(401).send({ message: 'unauthorized access!!' });
            }
            next();
        };

        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const storedUser = await usersCollection.findOne({ email: user.email });

            if (storedUser && await bcrypt.compare(user.password, storedUser.password)) {
                const token = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET, {
                    expiresIn: '365d',
                });
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                }).send({ success: true });
            } else {
                res.status(401).send({ success: false, message: 'Authentication failed' });
            }
        });

        app.get('/logout', async (req, res) => {
            try {
                res.clearCookie('token', {
                    maxAge: 0,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                }).send({ success: true });
                console.log('Logout successful');
            } catch (err) {
                res.status(500).send(err);
            }
        });


        app.get('/user', async (req, res) => {
            const token = req.cookies.token;
            if (!token) return res.status(401).send('Not authenticated');

            try {
                const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
                const user = await usersCollection.findOne({ email: decoded.email });
                if (user) {
                    res.send({ email: user.email });
                } else {
                    res.status(401).send('Not authenticated');
                }
            } catch (err) {
                res.status(401).send('Not authenticated');
            }
        });


        app.put('/user', async (req, res) => {
            const user = req.body;
            const hashedPassword = await bcrypt.hash(user.password, 10);
            const query = { email: user?.email };
            const isExist = await usersCollection.findOne(query);
            if (isExist) {
                return res.send(isExist);
            }
            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    email: user.email,
                    password: hashedPassword,
                    balance: 40,
                    timestamp: Date.now(),
                },
            };
            const result = await usersCollection.updateOne(query, updateDoc, options);
            res.send(result);
        });

        app.get('/user/:email', async (req, res) => {
            const email = req.params.email;
            const result = await usersCollection.findOne({ email });
            res.send(result);
        });

        app.get('/users', async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        app.patch('/users/update/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            const user = req.body;
            const query = { email };
            const updateDoc = {
                $set: { ...user, timestamp: Date.now() },
            };
            console.log(updateDoc);
            const result = await usersCollection.updateOne(query, updateDoc);
            res.send(result);
        });


        // Send Money
        app.post('/send-money', async (req, res) => {
            const { fromEmail, toEmail, amount } = req.body;

            const fromUser = await usersCollection.findOne({ email: fromEmail });
            const toUser = await usersCollection.findOne({ email: toEmail });

            if (!fromUser || !toUser) {
                return res.status(404).send({ success: false, message: 'User not found' });
            }

            if (fromUser.balance < amount) {
                return res.status(400).send({ success: false, message: 'Insufficient balance' });
            }

            await usersCollection.updateOne(
                { email: fromEmail },
                { $inc: { balance: -amount } }
            );

            await usersCollection.updateOne(
                { email: toEmail },
                { $inc: { balance: amount } }
            );

            res.send({ success: true, message: 'Money sent successfully' });
        });

        console.log('Pinged your deployment. You successfully connected to MongoDB!');
    } finally {
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('AxionDB Server is Running...');
});

app.listen(port, () => {
    console.log(`Server is Running on port ${port}`);
});
