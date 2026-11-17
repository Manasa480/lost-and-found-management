const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const readline = require('readline');

const db = new sqlite3.Database(
    path.join(__dirname, 'database.db')
);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter your registered email address: ', (email) => {
    const adminEmail = email.trim().toLowerCase();

    if (!adminEmail) {
        console.log('Email address is required.');
        rl.close();
        db.close();
        return;
    }

    db.run(
        `UPDATE users SET role = 'admin' WHERE email = ?`,
        [adminEmail],
        function (err) {
            if (err) {
                console.log('Error:', err.message);
            } else if (this.changes === 0) {
                console.log('Account not found. Register this email first.');
            } else {
                console.log('Success! Your account is now an admin.');
            }

            db.close();
            rl.close();
        }
    );
});