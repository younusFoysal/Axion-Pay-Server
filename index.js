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
        'http://localhost:5174',
        'https://axion-pay.web.app'
    ],
    credentials: true,
    optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const verifyToken = async (req, res, next) => {
    const { token } = req.cookies;
    //console.log('Token from cookie:', token);

    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.log(err);
        return res.status(401).send({ message: 'unauthorized access' });
    }
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
        const transactionsCollection = db.collection('transactions');
        const cashInRequestsCollection = db.collection('cashInRequests');
        const cashOutRequestsCollection = db.collection('cashOutRequests');




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
            const { identifier, password } = req.body; // identifier can be either email or phone

            try {
                const storedUser = await usersCollection.findOne({
                    $or: [{ email: identifier }, { phone: identifier }],
                });

                if (storedUser && await bcrypt.compare(password, storedUser.password)) {
                    const token = jwt.sign(
                        { email: storedUser.email, phone: storedUser.phone },
                        process.env.ACCESS_TOKEN_SECRET,
                        { expiresIn: '365d' }
                    );
                    res.cookie('token', token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                    }).send({ success: true });
                } else {
                    res.status(401).send({ success: false, message: 'Authentication failed' });
                }
            } catch (error) {
                console.error('Error during authentication:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
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
                    res.send({ user });
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
            let Balance = 0;
            if (user.role === 'user'){
                Balance = 40;
            } else if (user.role === 'agent'){
                Balance = 10000;
            } else {
                Balance = 0;
            }
            const updateDoc = {
                $set: {
                    name: user?.name,
                    role: user.role,
                    email: user.email,
                    phone: user?.phone,
                    password: hashedPassword,
                    status: user.status,
                    balance: Balance,
                    timestamp: Date.now(),
                },
            };
            console.log(updateDoc)
            const result = await usersCollection.updateOne(query, updateDoc, options);
            res.send(result);
        });

        // app.get('/user/:email', async (req, res) => {
        //     const email = req.params.email;
        //     const result = await usersCollection.findOne({ email });
        //     res.send(result);
        // });

        app.get('/user/:identifier', async (req, res) => {
            const identifier =  req.params.identifier;

            const storedUser = await usersCollection.findOne({
                $or: [{ email: identifier }, { phone: identifier }],
            });
            //console.log(storedUser)
            res.send(storedUser);
        });


        // get all users
        app.get('/users', async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        // get users - user
        app.get('/usersUser', async (req, res) => {
            const result = await usersCollection
                .find({role:"user"})
                .sort({ timestamp: -1 })
                .toArray();
            res.send(result);
        });

        // get users - agents
        app.get('/usersAgent', async (req, res) => {
            const result = await usersCollection
                .find({role:"agent"})
                .sort({ timestamp: -1 })
                .toArray();
            res.send(result);
        });

        //update users status - true or false
        app.patch('/users/update/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            const { status } = req.body; // Destructure status from req.body
            const query = { email };
            const updateDoc = {
                $set: { status, timestamp: Date.now() },
            };

            try {
                const result = await usersCollection.updateOne(query, updateDoc);
                if (result.modifiedCount > 0) {
                    res.send({ success: true, message: 'User status updated successfully' });
                } else {
                    res.send({ success: false, message: 'User not found or status not changed' });
                }
            } catch (error) {
                res.status(500).send({ success: false, message: 'Error updating user status', error });
            }
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


        // Send Money API
        app.post('/send-money', verifyToken, async (req, res) => {
            const { fromEmail, toEmail, amount, password , transType} = req.body;
            console.log('Received request:', fromEmail, toEmail, amount, password);

            try {
                const fromUser = await usersCollection.findOne({ email: fromEmail });
                const toUser = await usersCollection.findOne({ email: toEmail });

                console.log('From User:', fromUser);
                console.log('To User:', toUser);

                if (!fromUser || !toUser) {
                    console.log('User not found');
                    return res.status(404).send({ success: false, message: 'User not found' });
                }

                // Verify the password
                const isPasswordCorrect = await bcrypt.compare(password, fromUser.password);
                console.log('Is Password Correct:', isPasswordCorrect);

                if (!isPasswordCorrect) {
                    console.log('Incorrect password');
                    return res.status(401).send({ success: false, message: 'Incorrect password' });
                }

                // Check for sufficient balance
                console.log('From User Balance:', fromUser.balance, 'Amount:', amount);
                if (fromUser.balance < amount) {
                    console.log('Insufficient balance');
                    return res.status(400).send({ success: false, message: 'Insufficient balance' });
                }

                // Perform the transaction
                console.log('Performing transaction...');
                await usersCollection.updateOne(
                    { email: fromEmail },
                    { $inc: { balance: -amount } }
                );

                await usersCollection.updateOne(
                    { email: toEmail },
                    { $inc: { balance: amount } }
                );

                // Save transaction
                const transaction = {
                    fromEmail,
                    toEmail,
                    amount,
                    transType,
                    timestamp: new Date(),
                };

                await transactionsCollection.insertOne(transaction);

                console.log('Transaction successful');
                res.send({ success: true, message: 'Money sent successfully' });
            } catch (error) {
                console.error('Error during transaction:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        // TODO: Cash-in Request API
        // Cash-in Request API
        app.post('/request-cash-in', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, amount } = req.body;
            console.log('Received cash-in request:', agentEmail, userEmail, amount);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });

                console.log('Agent:', agent);
                console.log('User:', user);

                if (!agent || !user) {
                    console.log('Agent or user not found');
                    return res.status(404).send({ success: false, message: 'Agent or user not found' });
                }

                if (agent.role !== 'agent' || user.role !== 'user') {
                    console.log('Invalid roles');
                    return res.status(403).send({ success: false, message: 'Invalid roles' });
                }

                // Create cash-in request
                const cashInRequest = {
                    agentEmail,
                    userEmail,
                    amount,
                    status: 'pending',
                    requestedAt: new Date(),
                };

                const result = await cashInRequestsCollection.insertOne(cashInRequest);

                console.log('Cash-in request created:', result.insertedId);
                res.send({ success: true, message: 'Cash-in request created successfully', requestId: result.insertedId });
            } catch (error) {
                console.error('Error creating cash-in request:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });



        // Approve Cash In Request
        app.post('/approve-cash-in', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, requestId } = req.body;
            console.log('Received cash-in approval request:', agentEmail, userEmail, requestId);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });
                const cashInRequest = await cashInRequestsCollection.findOne({ _id: new ObjectId(requestId) });

                console.log('Agent:', agent);
                console.log('User:', user);
                console.log('Cash-In Request:', cashInRequest);

                if (!agent || !user || !cashInRequest) {
                    console.log('Agent, user, or request not found');
                    return res.status(404).send({ success: false, message: 'Agent, user, or request not found' });
                }

                // // Verify the password
                // const isPasswordCorrect = await bcrypt.compare(password, agent.password);
                // console.log('Is Password Correct:', isPasswordCorrect);
                //
                // if (!isPasswordCorrect) {
                //     console.log('Incorrect password');
                //     return res.status(401).send({ success: false, message: 'Incorrect password' });
                // }

                // Check for sufficient balance
                const amount = cashInRequest.amount;
                console.log('Agent Balance:', agent.balance, 'Amount:', amount);
                if (agent.balance < amount) {
                    console.log('Insufficient balance');
                    return res.status(400).send({ success: false, message: 'Insufficient balance' });
                }

                // Perform the transaction
                console.log('Performing cash-in transaction...');
                await usersCollection.updateOne(
                    { email: agentEmail },
                    { $inc: { balance: -amount } }
                );

                await usersCollection.updateOne(
                    { email: userEmail },
                    { $inc: { balance: amount } }
                );

                // Save transaction
                const transaction = {
                    fromEmail: agentEmail,
                    toEmail: userEmail,
                    amount,
                    transType: 'cash-in',
                    timestamp: new Date(),
                };

                await transactionsCollection.insertOne(transaction);

                // Mark the request as approved
                await cashInRequestsCollection.updateOne(
                    { _id: new ObjectId(requestId) },
                    { $set: { status: 'approved', approvedAt: new Date() } }
                );

                console.log('Cash-in transaction successful');
                res.send({ success: true, message: 'Cash-in request approved successfully' });
            } catch (error) {
                console.error('Error during cash-in approval:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        // Reject Cash In Request
        app.post('/reject-cash-in', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, requestId } = req.body;
            console.log('Received cash-in approval request:', agentEmail, userEmail, requestId);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });
                const cashInRequest = await cashInRequestsCollection.findOne({ _id: new ObjectId(requestId) });

                console.log('Agent:', agent);
                console.log('User:', user);
                console.log('Cash-In Request:', cashInRequest);

                if (!agent || !user || !cashInRequest) {
                    console.log('Agent, user, or request not found');
                    return res.status(404).send({ success: false, message: 'Agent, user, or request not found' });
                }

                // Mark the request as approved
                await cashInRequestsCollection.updateOne(
                    { _id: new ObjectId(requestId) },
                    { $set: { status: 'rejected', rejectedAt: new Date() } }
                );

                console.log('Cash-in rejection successful');
                res.send({ success: true, message: 'Cash-in request rejected successfully' });
            } catch (error) {
                console.error('Error during cash-in rejection:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });



        app.get('/request-cash-in', verifyToken, async (req, res) => {
            try {
                const cashInRequests = await cashInRequestsCollection.find().toArray();
                console.log('Cash-in requests retrieved:', cashInRequests);
                res.send({ success: true, cashInRequests });
            } catch (error) {
                console.error('Error retrieving cash-in requests:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        app.get('/request-cash-in/:email', verifyToken, async (req, res) => {
            try {
                const email = req.params.email;

                const cashInRequests = await cashInRequestsCollection
                    .find({ agentEmail: email})
                    .sort({ requestedAt: -1 })
                    .toArray();
                console.log('Cash-in requests retrieved:', cashInRequests);
                res.send({ success: true, cashInRequests });
            } catch (error) {
                console.error('Error retrieving cash-in requests:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });



        // TODO:  Cash-Out Request API
        // Cash Out Request Api
        app.post('/request-cash-out', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, amount, password} = req.body;
            console.log('Received cash-out request:', agentEmail, userEmail, amount);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });

                console.log('Agent:', agent);
                console.log('User:', user);

                if (!agent || !user) {
                    console.log('Agent or user not found');
                    return res.status(404).send({ success: false, message: 'Agent or user not found' });
                }

                if (agent.role !== 'agent' || user.role !== 'user') {
                    console.log('Invalid roles');
                    return res.status(403).send({ success: false, message: 'Invalid roles' });
                }


                // Verify the password
                const isPasswordCorrect = await bcrypt.compare(password, user.password);
                console.log('Is Password Correct:', isPasswordCorrect);

                if (!isPasswordCorrect) {
                    console.log('Incorrect password');
                    return res.status(401).send({ success: false, message: 'Incorrect password' });
                }


                // Create cash-out request
                const cashOutRequest = {
                    agentEmail,
                    userEmail,
                    amount,
                    fee: amount * 0.015,
                    status: 'pending',
                    requestedAt: new Date(),
                };

                const result = await cashOutRequestsCollection.insertOne(cashOutRequest);

                console.log('Cash-out request created:', result.insertedId);
                res.send({ success: true, message: 'Cash-out request created successfully', requestId: result.insertedId });
            } catch (error) {
                console.error('Error creating cash-out request:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });



        // cash Out Approve Api
        app.post('/approve-cash-out', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, requestId } = req.body;
            console.log('Received cash-out approval request:', agentEmail, userEmail, requestId);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });
                const cashOutRequest = await cashOutRequestsCollection.findOne({ _id: new ObjectId(requestId) });

                console.log('Agent:', agent);
                console.log('User:', user);
                console.log('Cash-Out Request:', cashOutRequest);

                if (!agent || !user || !cashOutRequest) {
                    console.log('Agent, user, or request not found');
                    return res.status(404).send({ success: false, message: 'Agent, user, or request not found' });
                }

                if (agent.role !== 'agent' || user.role !== 'user') {
                    console.log('Invalid roles');
                    return res.status(403).send({ success: false, message: 'Invalid roles' });
                }

                // // Verify the password
                // const isPasswordCorrect = await bcrypt.compare(password, agent.password);
                // console.log('Is Password Correct:', isPasswordCorrect);
                //
                // if (!isPasswordCorrect) {
                //     console.log('Incorrect password');
                //     return res.status(401).send({ success: false, message: 'Incorrect password' });
                // }

                const amount = cashOutRequest.amount;
                const fee = cashOutRequest.fee;
                const totalDeduction = amount + fee;

                // Check for sufficient balance
                console.log('User Balance:', user.balance, 'Total Deduction:', totalDeduction);
                if (user.balance < totalDeduction) {
                    console.log('Insufficient balance');
                    return res.status(400).send({ success: false, message: 'Insufficient balance' });
                }

                // Perform the transaction
                console.log('Performing cash-out transaction...');
                await usersCollection.updateOne(
                    { email: userEmail },
                    { $inc: { balance: -totalDeduction } }
                );

                await usersCollection.updateOne(
                    { email: agentEmail },
                    { $inc: { balance: amount + fee } }
                );

                // Save transaction
                const transaction = {
                    fromEmail: userEmail,
                    toEmail: agentEmail,
                    amount,
                    fee,
                    transType: 'cash-out',
                    timestamp: new Date(),
                };

                await transactionsCollection.insertOne(transaction);

                // Mark the request as approved
                await cashOutRequestsCollection.updateOne(
                    { _id: new ObjectId(requestId) },
                    { $set: { status: 'approved', approvedAt: new Date() } }
                );

                console.log('Cash-out transaction successful');
                res.send({ success: true, message: 'Cash-out request approved successfully' });
            } catch (error) {
                console.error('Error during cash-out approval:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        app.get('/request-cash-out', verifyToken, async (req, res) => {
            try {
                const cashOutRequests = await cashOutRequestsCollection.find().toArray();
                console.log('Cash-out requests retrieved:', cashOutRequests);
                res.send({ success: true, cashOutRequests });
            } catch (error) {
                console.error('Error retrieving cash-out requests:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        app.get('/request-cash-out/:email', verifyToken, async (req, res) => {
            try {
                const email = req.params.email;

                const cashOutRequests = await cashOutRequestsCollection
                    .find({ agentEmail: email})
                    .sort({ requestedAt: -1 })
                    .toArray();
                console.log('Cash-in requests retrieved:', cashOutRequests);
                res.send({ success: true, cashOutRequests });
            } catch (error) {
                console.error('Error retrieving cash-in requests:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        // Reject Cash In Request
        app.post('/reject-cash-out', verifyToken, async (req, res) => {
            const { agentEmail, userEmail, requestId } = req.body;
            console.log('Received cash-in approval request:', agentEmail, userEmail, requestId);

            try {
                const agent = await usersCollection.findOne({ email: agentEmail });
                const user = await usersCollection.findOne({ email: userEmail });
                const cashOutRequest = await cashOutRequestsCollection.findOne({ _id: new ObjectId(requestId) });

                console.log('Agent:', agent);
                console.log('User:', user);
                console.log('Cash-Out Request:', cashOutRequest);

                if (!agent || !user || !cashOutRequest) {
                    console.log('Agent, user, or request not found');
                    return res.status(404).send({ success: false, message: 'Agent, user, or request not found' });
                }

                // Mark the request as approved
                await cashOutRequestsCollection.updateOne(
                    { _id: new ObjectId(requestId) },
                    { $set: { status: 'rejected', rejectedAt: new Date() } }
                );

                console.log('Cash-Out rejection successful');
                res.send({ success: true, message: 'Cash-Out request rejected successfully' });
            } catch (error) {
                console.error('Error during cash-Out rejection:', error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        // get all trans of a user
        app.get('/transactions/:email',verifyToken, async (req, res) => {
            const email = req.params.email;

            const transactions = await transactionsCollection
                .find({ $or: [{ fromEmail: email }, { toEmail: email }] })
                .sort({ timestamp: -1 })
                .limit(100)
                .toArray();

            res.send(transactions);
        });

        // get all transactions with pagination
        app.get('/transactions', verifyToken, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 15;
                const skip = (page - 1) * limit;

                const totalTransactions = await transactionsCollection.countDocuments();
                const totalPages = Math.ceil(totalTransactions / limit);

                const transactions = await transactionsCollection
                    .find({})
                    .sort({ timestamp: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({
                    transactions,
                    totalPages,
                });
            } catch (error) {
                console.error('Error fetching transactions:', error);
                res.status(500).send('Error fetching transactions');
            }
        });




        // Check Password
        app.post('/check-password', async (req, res) => {
            const { password } = req.body;
            const token = req.cookies.token;

            if (!token) return res.status(401).send('Not authenticated');

            try {
                const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
                const user = await usersCollection.findOne({ email: decoded.email });

                if (user && await bcrypt.compare(password, user.password)) {
                    return res.send({ success: true });
                } else {
                    return res.status(401).send({ success: false, message: 'Incorrect password' });
                }
            } catch (err) {
                res.status(401).send('Not authenticated');
            }
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
