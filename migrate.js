const { pool } = require('./db.js');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');

async function migrate() {
    try {
        // Seed admins
        const admins = [
            { username: 'aadrita', password: 'psycho' },
            { username: 'newtondev', password: 'devadmin' },
            { username: 'jon', password: 'spiderman' },
            { username: 'avinash', password: 'bruh' },
            { username: 'jessie', password: 'gosling' }
        ];

        for (const admin of admins) {
            const hashedPassword = await bcrypt.hash(admin.password, 10);
            await pool.query(
                'INSERT INTO users (username, password) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING',
                [admin.username, hashedPassword]
            );
        }
        console.log('Admins seeded');

        // Migrate data.json (if it exists)
        let data;
        try {
            const jsonData = await fs.readFile('./data.json', 'utf8');
            data = JSON.parse(jsonData);
        } catch (err) {
            console.log('No data.json found, skipping migration');
            await pool.end();
            return;
        }

        // Migrate modules
        for (const module of data.modules) {
            await pool.query(
                'INSERT INTO modules (id, name, instructions) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING',
                [module.id, module.name, module.instructions]
            );
        }

        // Migrate questions (created_by = null for existing ones)
        for (const question of data.questions) {
            await pool.query(
                `INSERT INTO questions (id, module_id, type, question, option_a, option_b, option_c, option_d, option_e, 
                 correct_answer, explanation, tags, created_by) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
                 ON CONFLICT (id) DO NOTHING`,
                [
                    question.id, question.module_id, question.type, question.question,
                    question.option_a, question.option_b, question.option_c, question.option_d, question.option_e,
                    question.correct_answer, question.explanation, question.tags, null
                ]
            );
        }

        console.log('Data migrated successfully');
    } catch (err) {
        console.error('Migration error:', err);
    } finally {
        await pool.end();
    }
}

migrate();