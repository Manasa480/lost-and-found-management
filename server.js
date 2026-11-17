
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');

const app = express();
const PORT = 3000;

// ---------------- FOLDERS ----------------

const uploadFolder = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadFolder)) {
    fs.mkdirSync(uploadFolder, { recursive: true });
}

// ---------------- DATABASE ----------------

const db = new sqlite3.Database(
    path.join(__dirname, 'database.db'),
    (err) => {
        if (err) {
            console.error('Database connection error:', err.message);
        } else {
            console.log('SQLite database connected successfully');
        }
    }
);

// ---------------- MIDDLEWARE ----------------

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadFolder));

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-this-to-a-long-random-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ---------------- IMAGE UPLOAD ----------------

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadFolder);
    },
    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname).toLowerCase();
        const uniqueName = Date.now() + '-' +
            Math.round(Math.random() * 1E9) + extension;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed.'));
        }
    }
});

// ---------------- AUTHENTICATION ----------------

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/admin-login');
    }

    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access denied. Admin permission required.');
    }

    next();
}

// ---------------- DATABASE HELPERS ----------------

function runSQL(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function getSQL(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// ---------------- DATABASE INITIALIZATION ----------------

async function initializeDatabase() {

    await runSQL(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    `);

    // Add role column to an older database if necessary
    const columns = await new Promise((resolve, reject) => {
        db.all('PRAGMA table_info(users)', [], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });

    if (!columns.some(column => column.name === 'role')) {
        await runSQL(`
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        `);
        console.log('Admin role column added');
    }

    await runSQL(`
        CREATE TABLE IF NOT EXISTS lost_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            lost_date TEXT NOT NULL,
            location TEXT NOT NULL,
            contact TEXT NOT NULL,
            image TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    await runSQL(`
        CREATE TABLE IF NOT EXISTS found_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            found_date TEXT NOT NULL,
            location TEXT NOT NULL,
            contact TEXT NOT NULL,
            image TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    console.log('All database tables are ready');
}

// ---------------- HOME PAGE ----------------

app.get('/', (req, res) => {
    res.render('index');
});

// ---------------- USER REGISTRATION ----------------

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password) {
        return res.status(400).send('Please fill all fields.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await runSQL(
            `INSERT INTO users (name, email, phone, password, role)
             VALUES (?, ?, ?, ?, 'user')`,
            [
                name.trim(),
                email.trim().toLowerCase(),
                phone.trim(),
                hashedPassword
            ]
        );

        res.redirect('/login');

    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            return res.send('Email already registered. Please login.');
        }

        console.error('Registration error:', err.message);
        res.status(500).send('Registration failed.');
    }
});

// ---------------- USER LOGIN ----------------

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Enter email and password.');
    }

    db.get(
        'SELECT * FROM users WHERE email = ?',
        [email.trim().toLowerCase()],
        async (err, user) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Database error.');
            }

            if (!user) {
                return res.send('Account not found. Please register.');
            }

            try {
                const validPassword = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!validPassword) {
                    return res.send('Incorrect password.');
                }

                req.session.regenerate((sessionError) => {
                    if (sessionError) {
                        return res.status(500).send('Unable to start session.');
                    }

                    req.session.user = {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role || 'user'
                    };

                    res.redirect('/dashboard');
                });

            } catch (error) {
                console.error(error);
                res.status(500).send('Login failed.');
            }
        }
    );
});

// ---------------- USER DASHBOARD ----------------

app.get('/dashboard', requireLogin, (req, res) => {
    res.render('dashboard', {
        user: req.session.user
    });
});

// ---------------- REPORT LOST ITEM ----------------

app.get('/report-lost', requireLogin, (req, res) => {
    res.render('report-lost');
});

app.post('/report-lost', requireLogin, (req, res) => {

    upload.single('itemImage')(req, res, (uploadError) => {

        if (uploadError) {
            return res.status(400).send(uploadError.message);
        }

        const {
            itemName,
            category,
            description,
            lostDate,
            location,
            contact
        } = req.body;

        if (!itemName || !category || !description ||
            !lostDate || !location || !contact) {
            return res.status(400).send('Please fill all required fields.');
        }

        const image = req.file ? req.file.filename : null;

        db.run(
            `INSERT INTO lost_items
            (user_id, item_name, category, description,
             lost_date, location, contact, image)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.session.user.id,
                itemName.trim(),
                category,
                description.trim(),
                lostDate,
                location.trim(),
                contact.trim(),
                image
            ],
            function (err) {

                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Unable to save lost item.');
                }

                res.send(`
                    <h2>Lost item reported successfully!</h2>
                    <a href="/dashboard">Back to Dashboard</a><br><br>
                    <a href="/items">View Lost Items</a>
                `);
            }
        );
    });
});

// ---------------- REPORT FOUND ITEM ----------------

app.get('/report-found', requireLogin, (req, res) => {
    res.render('report-found');
});

app.post('/report-found', requireLogin, (req, res) => {

    upload.single('itemImage')(req, res, (uploadError) => {

        if (uploadError) {
            return res.status(400).send(uploadError.message);
        }

        const {
            itemName,
            category,
            description,
            foundDate,
            location,
            contact
        } = req.body;

        if (!itemName || !category || !description ||
            !foundDate || !location || !contact) {
            return res.status(400).send('Please fill all required fields.');
        }

        const image = req.file ? req.file.filename : null;

        db.run(
            `INSERT INTO found_items
            (user_id, item_name, category, description,
             found_date, location, contact, image)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.session.user.id,
                itemName.trim(),
                category,
                description.trim(),
                foundDate,
                location.trim(),
                contact.trim(),
                image
            ],
            function (err) {

                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Unable to save found item.');
                }

                res.send(`
                    <h2>Found item reported successfully!</h2>
                    <a href="/dashboard">Back to Dashboard</a><br><br>
                    <a href="/found-items">View Found Items</a>
                `);
            }
        );
    });
});

// ---------------- VIEW LOST ITEMS ----------------

app.get('/items', requireLogin, (req, res) => {

    db.all(
        'SELECT * FROM lost_items ORDER BY id DESC',
        [],
        (err, items) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Unable to load lost items.');
            }

            res.render('lost-items', { items });
        }
    );
});

// ---------------- VIEW FOUND ITEMS ----------------

app.get('/found-items', requireLogin, (req, res) => {

    db.all(
        'SELECT * FROM found_items ORDER BY id DESC',
        [],
        (err, items) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Unable to load found items.');
            }

            res.render('view-found', { items });
        }
    );
});

// ---------------- SEARCH ITEMS ----------------

app.get('/search', requireLogin, (req, res) => {

    const keyword = (req.query.keyword || '').trim();

    const type = ['all', 'lost', 'found'].includes(req.query.type)
        ? req.query.type
        : 'all';

    const searchValue = `%${keyword}%`;

    let sql;
    let params;

    if (type === 'lost') {

        sql = `
            SELECT item_name, category, description,
                   lost_date AS item_date, location,
                   contact, image, 'Lost' AS item_type, id
            FROM lost_items
            WHERE item_name LIKE ? OR category LIKE ?
            ORDER BY id DESC
        `;

        params = [searchValue, searchValue];

    } else if (type === 'found') {

        sql = `
            SELECT item_name, category, description,
                   found_date AS item_date, location,
                   contact, image, 'Found' AS item_type, id
            FROM found_items
            WHERE item_name LIKE ? OR category LIKE ?
            ORDER BY id DESC
        `;

        params = [searchValue, searchValue];

    } else {

        sql = `
            SELECT *
            FROM (
                SELECT item_name, category, description,
                       lost_date AS item_date, location,
                       contact, image, 'Lost' AS item_type, id
                FROM lost_items
                WHERE item_name LIKE ? OR category LIKE ?

                UNION ALL

                SELECT item_name, category, description,
                       found_date AS item_date, location,
                       contact, image, 'Found' AS item_type, id
                FROM found_items
                WHERE item_name LIKE ? OR category LIKE ?
            )
            ORDER BY id DESC
        `;

        params = [
            searchValue,
            searchValue,
            searchValue,
            searchValue
        ];
    }

    db.all(sql, params, (err, items) => {

        if (err) {
            console.error('Search error:', err.message);
            return res.status(500).send('Unable to search items.');
        }

        res.render('search-items', {
            items,
            keyword,
            type
        });
    });
});

// ---------------- AUTOMATIC ITEM MATCHING ----------------

app.get('/matches', requireLogin, (req, res) => {

    const sql = `
        SELECT
            l.item_name AS lost_name,
            l.category AS category,
            l.location AS lost_location,
            l.lost_date AS lost_date,
            f.item_name AS found_name,
            f.location AS found_location,
            f.found_date AS found_date,
            f.contact AS found_contact
        FROM lost_items l
        INNER JOIN found_items f
        ON LOWER(TRIM(l.item_name)) = LOWER(TRIM(f.item_name))
        AND LOWER(TRIM(l.category)) = LOWER(TRIM(f.category))
        ORDER BY l.id DESC
    `;

    db.all(sql, [], (err, matches) => {

        if (err) {
            console.error('Matching error:', err.message);
            return res.status(500).send('Unable to find matching items.');
        }

        res.render('matches', { matches });
    });
});

// ---------------- ADMIN LOGIN ----------------

app.get('/admin-login', (req, res) => {
    res.render('admin-login');
});

app.post('/admin-login', (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Enter admin email and password.');
    }

    db.get(
        'SELECT * FROM users WHERE email = ?',
        [email.trim().toLowerCase()],
        async (err, user) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Database error.');
            }

            if (!user) {
                return res.status(401).send('Invalid admin email or password.');
            }

            try {
                const validPassword = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!validPassword || user.role !== 'admin') {
                    return res.status(401).send('Invalid admin email or password.');
                }

                req.session.regenerate((sessionError) => {

                    if (sessionError) {
                        return res.status(500).send('Unable to start session.');
                    }

                    req.session.user = {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role
                    };

                    res.redirect('/admin-dashboard');
                });

            } catch (error) {
                console.error(error);
                res.status(500).send('Admin login failed.');
            }
        }
    );
});

// ---------------- ADMIN DASHBOARD ----------------

app.get('/admin-dashboard', requireAdmin, async (req, res) => {

    try {
        const users = await getSQL(
            'SELECT COUNT(*) AS total FROM users'
        );

        const lost = await getSQL(
            'SELECT COUNT(*) AS total FROM lost_items'
        );

        const found = await getSQL(
            'SELECT COUNT(*) AS total FROM found_items'
        );

        res.render('admin-dashboard', {
            totalUsers: users.total,
            totalLost: lost.total,
            totalFound: found.total,
            admin: req.session.user
        });

    } catch (err) {
        console.error('Admin dashboard error:', err.message);
        res.status(500).send('Unable to load admin dashboard.');
    }
});

// ---------------- MANAGE USERS ----------------

app.get('/admin-users', requireAdmin, (req, res) => {

    db.all(
        'SELECT id, name, email, phone FROM users ORDER BY id DESC',
        [],
        (err, users) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Unable to load users.');
            }

            res.render('admin-users', {
                users,
                admin: req.session.user
            });
        }
    );
});

// ---------------- MANAGE LOST ITEMS ----------------

app.get('/admin-lost-items', requireAdmin, (req, res) => {

    db.all(
        'SELECT * FROM lost_items ORDER BY id DESC',
        [],
        (err, items) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Unable to load lost items.');
            }

            res.render('admin-lost-items', {
                items,
                admin: req.session.user
            });
        }
    );
});

// ---------------- MANAGE FOUND ITEMS ----------------

app.get('/admin-found-items', requireAdmin, (req, res) => {

    db.all(
        'SELECT * FROM found_items ORDER BY id DESC',
        [],
        (err, items) => {

            if (err) {
                console.error(err.message);
                return res.status(500).send('Unable to load found items.');
            }

            res.render('admin-found-items', {
                items,
                admin: req.session.user
            });
        }
    );
});
// Admin: Delete a lost item
app.post('/admin-delete-lost/:id', requireAdmin, (req, res) => {
    db.run(
        'DELETE FROM lost_items WHERE id = ?',
        [req.params.id],
        function (err) {
            if (err) {
                console.error('Delete lost item error:', err.message);
                return res.status(500).send('Unable to delete lost item.');
            }

            res.redirect('/admin-lost-items');
        }
    );
});
// Admin: Delete a found item
app.post('/admin-delete-found/:id', requireAdmin, (req, res) => {
    db.run(
        'DELETE FROM found_items WHERE id = ?',
        [req.params.id],
        function (err) {
            if (err) {
                console.error('Delete found item error:', err.message);
                return res.status(500).send('Unable to delete found item.');
            }

            res.redirect('/admin-found-items');
        }
    );
});
// ---------------- ADMIN LOGOUT ----------------

app.get('/admin-logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            return res.status(500).send('Unable to logout.');
        }

        res.redirect('/admin-login');
    });
});

// ---------------- USER LOGOUT ----------------

app.get('/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            return res.status(500).send('Unable to logout.');
        }

        res.redirect('/login');
    });
});

// ---------------- ERROR HANDLER ----------------

app.use((err, req, res, next) => {
    console.error('Application error:', err);
    res.status(500).send(err.message || 'Something went wrong.');
});

// ---------------- START SERVER ----------------

initializeDatabase()
    .then(() => {

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });

    })
    .catch((err) => {

        console.error('Database initialization failed:', err.message);
        process.exit(1);

    });
