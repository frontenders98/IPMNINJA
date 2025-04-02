const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const bcrypt = require('bcrypt');
const { pool } = require('./db.js');

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const userSession = session({
    name: 'userSession',
    secret: 'some-long-random-string-user-123',
    resave: false,
    saveUninitialized: false,
    store: new MemoryStore({ checkPeriod: 86400000 }),
    cookie: { maxAge: 24 * 60 * 60 * 1000, secure: false, httpOnly: true }
});

const adminSession = session({
    name: 'adminSession',
    secret: 'some-long-random-string-admin-456',
    resave: false,
    saveUninitialized: false,
    store: new MemoryStore({ checkPeriod: 86400000 }),
    cookie: { maxAge: 24 * 60 * 60 * 1000, secure: false, httpOnly: true }
});

app.use(userSession);
app.use('/admin*', adminSession);

function ensureUserAuthenticated(req, res, next) {
    console.log('User auth check - User session:', req.session);
    if (req.session.userId && (req.session.role === 'user' || req.session.role === 'admin')) {
        return next();
    }
    console.log('User not authenticated, redirecting to /');
    res.redirect('/');
}

function ensureAdminAuthenticated(req, res, next) {
    console.log('Admin auth check - Admin session:', req.session);
    if (req.session.userId && req.session.role === 'admin') {
        return next();
    }
    console.log('Admin not authenticated, redirecting to /admin-login');
    res.redirect('/admin-login');
}

app.get('/', (req, res) => {
    console.log('GET / - User session:', req.session);
    res.render('user-login', { error: null });
});

app.post('/user-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.role = user.role;
            console.log('User logged in - User session:', req.session);
            res.redirect('/index');
        } else {
            res.render('user-login', { error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error('User login error:', err.stack);
        res.render('user-login', { error: 'Server error' });
    }
});

app.get('/index', ensureUserAuthenticated, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM modules ORDER BY id');
        console.log('GET /index - User session:', req.session, 'Modules:', result.rows.length);
        res.render('index', { modules: result.rows });
    } catch (err) {
        console.error('Index fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/user-logout', (req, res) => {
    console.log('POST /user-logout - User session before:', req.session);
    req.session.destroy((err) => {
        if (err) console.error('User logout error:', err);
        console.log('User session destroyed');
        res.redirect('/');
    });
});

app.get('/admin-login', (req, res) => {
    console.log('GET /admin-login - Admin session:', req.session);
    res.render('login', { error: null });
});

app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1 AND role = $2', [username, 'admin']);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.role = user.role;
            console.log('Admin logged in - Admin session:', req.session);
            res.redirect('/admin');
        } else {
            res.render('login', { error: 'Invalid admin credentials' });
        }
    } catch (err) {
        console.error('Admin login error:', err.stack);
        res.render('login', { error: 'Server error' });
    }
});

app.post('/admin-logout', (req, res) => {
    console.log('POST /admin-logout - Admin session before:', req.session);
    req.session.destroy((err) => {
        if (err) console.error('Admin logout error:', err);
        console.log('Admin session destroyed');
        res.redirect('/admin-login');
    });
});

app.get('/admin', ensureAdminAuthenticated, async (req, res) => {
    try {
        const modulesResult = await pool.query('SELECT * FROM modules ORDER BY id');
        console.log('GET /admin - Admin session:', req.session, 'Modules:', modulesResult.rows.length);
        res.render('admin', { modules: modulesResult.rows });
    } catch (err) {
        console.error('Admin fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/add-module', ensureAdminAuthenticated, async (req, res) => {
    const { name, instructions } = req.body;
    try {
        await pool.query('INSERT INTO modules (name, instructions) VALUES ($1, $2)', [name, instructions || null]);
        console.log('Module added - Admin session:', req.session);
        res.redirect('/admin');
    } catch (err) {
        console.error('Add module error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/edit-module/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId } = req.params;
    const { name, instructions } = req.body;
    try {
        await pool.query('UPDATE modules SET name = $1, instructions = $2 WHERE id = $3', [name, instructions || null, moduleId]);
        console.log(`Module ${moduleId} edited - Admin session:`, req.session);
        res.json({ success: true });
    } catch (err) {
        console.error('Edit module error:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to edit module' });
    }
});

app.post('/admin/delete-module/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId } = req.params;
    console.log(`Attempting to delete module ${moduleId} - Admin session:`, req.session);
    try {
        const result = await pool.query('DELETE FROM modules WHERE id = $1', [moduleId]);
        console.log(`Delete result: ${result.rowCount} rows affected`);
        if (result.rowCount > 0) {
            res.json({ success: true });
        } else {
            res.status(404).json({ success: false, message: 'Module not found' });
        }
    } catch (err) {
        console.error('Delete module error:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to delete module' });
    }
});

app.get('/admin/questions/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        const questionResult = await pool.query('SELECT * FROM questions WHERE module_id = $1', [moduleId]);
        const module = moduleResult.rows[0];
        const questions = questionResult.rows;
        if (!module) return res.status(404).send('Module not found');
        console.log(`GET /admin/questions/${moduleId} - Admin session:`, req.session);
        res.render('questions', { module, questions });
    } catch (err) {
        console.error('Questions fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/add-question/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const { type, question, option_a, option_b, option_c, option_d, option_e, correct_answer_qa, correct_answer_mcq_va, explanation, tags } = req.body;
    const correct_answer = type === 'QA' ? correct_answer_qa : correct_answer_mcq_va;

    if (!type || !question || !correct_answer) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO questions (module_id, type, question, option_a, option_b, option_c, option_d, option_e, 
             correct_answer, explanation, tags) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
            [moduleId, type, question, option_a || null, option_b || null, option_c || null, option_d || null, 
             option_e || null, correct_answer, explanation || null, tags || null]
        );
        console.log(`Question added to module ${moduleId} - Admin session:`, req.session);
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        console.error('Add question error:', err.stack);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/admin/edit-question/:moduleId/:questionId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId, questionId } = req.params;
    const { type, question, option_a, option_b, option_c, option_d, option_e, correct_answer_qa, correct_answer_mcq_va, explanation, tags } = req.body;
    const correct_answer = type === 'QA' ? correct_answer_qa : correct_answer_mcq_va;

    if (!type || !question || !correct_answer) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    try {
        const result = await pool.query(
            `UPDATE questions 
             SET type = $1, question = $2, option_a = $3, option_b = $4, option_c = $5, option_d = $6, 
                 option_e = $7, correct_answer = $8, explanation = $9, tags = $10, version = version + 1 
             WHERE id = $11 AND module_id = $12 
             RETURNING id`,
            [type, question, option_a || null, option_b || null, option_c || null, option_d || null, 
             option_e || null, correct_answer, explanation || null, tags || null, questionId, moduleId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'Question not found' });
        }
        console.log(`Question ${questionId} edited in module ${moduleId} - Admin session:`, req.session);
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        console.error('Edit question error:', err.stack);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/admin/delete-question/:moduleId/:questionId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId, questionId } = req.params;
    try {
        await pool.query('DELETE FROM questions WHERE id = $1 AND module_id = $2', [questionId, moduleId]);
        console.log(`Question ${questionId} deleted from module ${moduleId} - Admin session:`, req.session);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete question error:', err.stack);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/exam/:moduleId', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        if (moduleResult.rows.length === 0) return res.status(404).send('Module not found');

        const questionResult = await pool.query(
            'SELECT * FROM questions WHERE module_id = $1 ORDER BY id',
            [moduleId]
        );
        const questions = questionResult.rows;
        if (questions.length === 0) return res.send('No questions in this module');

        console.log(`GET /exam/${moduleId} - User session:`, req.session);
        res.render('exam', {
            questions,
            module: moduleResult.rows[0],
            startIndex: 0 // No progress tracking
        });
    } catch (err) {
        console.error('Exam fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/exam/:moduleId/submit', ensureUserAuthenticated, async (req, res) => {
    const { questionId, answer } = req.body || {};
    if (!questionId || !answer) {
        return res.status(400).json({ success: false, message: 'Missing questionId or answer' });
    }
    res.json({ success: true }); // No DB save, just acknowledge
});

pool.connect().then(() => {
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
}).catch((err) => {
    console.error('Failed to connect to database:', err.stack);
    process.exit(1);
});
