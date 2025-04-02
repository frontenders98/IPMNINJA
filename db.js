const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client:', err.stack);
    process.exit(-1);
});

module.exports = { pool };
