const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DB_URL
});

// Function to create the users table
const createUsersTable = async () => {
    try {
        console.log('Attempting to create users table...');
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Users table created or already exists');
    } catch (err) {
        console.error('Error creating users table:', err);
        throw err; // Rethrow to ensure server doesn't start if table creation fails
    }
};

// Initialize the database by creating the table
(async () => {
    try {
        await pool.connect(); // Ensure connection is established
        await createUsersTable();
    } catch (err) {
        console.error('Database initialization failed:', err);
        process.exit(1); // Exit process if initialization fails
    }
})();

module.exports = pool;