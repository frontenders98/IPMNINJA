const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }  // Neon requires SSL
});

async function initializeDatabase() {
    try {
        console.log('Connecting to database...');
        const client = await pool.connect();
        console.log('Connected successfully');

        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(10) NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS modules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                instructions TEXT
            );

            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                module_id INTEGER REFERENCES modules(id) ON DELETE CASCADE,
                type VARCHAR(3) CHECK (type IN ('QA', 'MCQ', 'VA')) NOT NULL,
                question TEXT NOT NULL,
                option_a TEXT,
                option_b TEXT,
                option_c TEXT,
                option_d TEXT,
                option_e TEXT,
                correct_answer TEXT NOT NULL,
                explanation TEXT,
                tags TEXT,
                image_path TEXT,
                created_by INTEGER REFERENCES users(id),
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_questions_module_id ON questions(module_id);
            CREATE INDEX IF NOT EXISTS idx_questions_created_by ON questions(created_by);
        `);

        await client.query(`
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS role VARCHAR(10) NOT NULL DEFAULT 'user',
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

            UPDATE users 
            SET role = 'admin' 
            WHERE username IN ('aadrita', 'newtondev', 'jon', 'avinash', 'jessie') 
            AND role IS NULL OR role != 'admin';

            UPDATE users 
            SET created_at = NOW() 
            WHERE created_at IS NULL;
        `);

        const newUsers = [
            { username: 'gungun', password: 'lethal', role: 'user' },
            { username: 'aarya', password: 'jennie', role: 'user' },
            { username: 'round', password: 'neil', role: 'user' },
            { username: 'rishav', password: 'goodboy', role: 'user' },
            { username: 'diya', password: 'emma', role: 'user' },
            { username: 'ayush', password: 'jawline', role: 'user' },
            { username: 'debraj', password: 'mathpro', role: 'user' }
        ];

        for (const user of newUsers) {
            const hashedPassword = await bcrypt.hash(user.password, 10);
            await client.query(`
                INSERT INTO users (username, password, role, created_at)
                VALUES ($1, $2, $3, NOW())
                ON CONFLICT (username) DO UPDATE
                SET password = $2, role = $3, created_at = NOW()
            `, [user.username, hashedPassword, user.role]);
        }

        console.log('Database tables, roles, and users initialized successfully');
        client.release();
    } catch (err) {
        console.error('Error initializing database:', err.stack);
    }
}

// Skip init on Render—Neon’s already populated
if (process.env.NODE_ENV !== 'production') {
    initializeDatabase().then(() => {
        console.log('Initialization complete');
    }).catch(err => {
        console.error('Initialization failed:', err.stack);
    });
}

module.exports = { pool };
