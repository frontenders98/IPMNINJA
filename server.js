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
    resave: true,
    saveUninitialized: false,
    store: new MemoryStore({ checkPeriod: 86400000 }),
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000,
        secure: false,
        httpOnly: true 
    }
});

const adminSession = session({
    name: 'adminSession',
    secret: 'some-long-random-string-admin-456',
    resave: true,
    saveUninitialized: false,
    store: new MemoryStore({ checkPeriod: 86400000 }),
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000,
        secure: false,
        httpOnly: true 
    }
});

app.use(userSession);
app.use('/admin*', adminSession);

async function keepDbAlive() {
    try {
        await pool.query('SELECT 1');
        console.log('Database ping successful');
    } catch (err) {
        console.error('Database ping failed:', err.stack);
    }
}
setInterval(keepDbAlive, 5 * 60 * 1000);

function ensureUserAuthenticated(req, res, next) {
    if (req.session.userId && (req.session.role === 'user' || req.session.role === 'admin')) {
        req.session.touch();
        return next();
    }
    res.redirect('/');
}

function ensureAdminAuthenticated(req, res, next) {
    if (req.session.userId && req.session.role === 'admin') {
        req.session.touch();
        return next();
    }
    res.redirect('/admin-login');
}

app.get('/keep-alive', (req, res) => {
    if (req.session.userId) {
        req.session.touch();
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, message: 'Not authenticated' });
    }
});

app.get('/', (req, res) => res.render('user-login', { error: null }));

app.post('/user-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.role = user.role;
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
        const moduleResult = await pool.query('SELECT * FROM modules ORDER BY id');
        const modules = moduleResult.rows;

        const questionResult = await pool.query('SELECT module_id, COUNT(*) as total FROM questions GROUP BY module_id');
        const answerResult = await pool.query(
            'SELECT q.module_id, COUNT(ua.question_id) as answered ' +
            'FROM questions q ' +
            'LEFT JOIN user_answers ua ON ua.question_id = q.id AND ua.user_id = $1 ' +
            'GROUP BY q.module_id',
            [req.session.userId]
        );
        const submissionResult = await pool.query(
            'SELECT DISTINCT q.module_id ' +
            'FROM user_answers ua ' +
            'JOIN questions q ON ua.question_id = q.id ' +
            'WHERE ua.user_id = $1',
            [req.session.userId]
        );

        const questionCounts = {};
        questionResult.rows.forEach(row => questionCounts[row.module_id] = parseInt(row.total));
        const answeredCounts = {};
        answerResult.rows.forEach(row => answeredCounts[row.module_id] = parseInt(row.answered));
        const submittedModules = new Set(submissionResult.rows.map(row => row.module_id));

        const modulesWithStatus = modules.map(module => ({
            ...module,
            isComplete: module.name.startsWith('Exam Mode') && submittedModules.has(module.id)
        }));

        res.render('index', { modules: modulesWithStatus });
    } catch (err) {
        console.error('Index fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/user-logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('User logout error:', err);
        res.redirect('/');
    });
});

app.get('/admin-login', (req, res) => res.render('login', { error: null }));

app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1 AND role = $2', [username, 'admin']);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.role = user.role;
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
    req.session.destroy((err) => {
        if (err) console.error('Admin logout error:', err);
        res.redirect('/admin-login');
    });
});

app.get('/admin', ensureAdminAuthenticated, async (req, res) => {
    try {
        const modulesResult = await pool.query('SELECT * FROM modules ORDER BY id');
        res.render('admin', { modules: modulesResult.rows });
    } catch (err) {
        console.error('Admin fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.get('/admin/overview', ensureAdminAuthenticated, async (req, res) => {
    try {
        const modulesResult = await pool.query('SELECT COUNT(*) FROM modules');
        const totalModules = parseInt(modulesResult.rows[0].count);

        const questionsResult = await pool.query('SELECT COUNT(*) FROM questions');
        const totalQuestions = parseInt(questionsResult.rows[0].count);

        const activeUsersResult = await pool.query(
            `SELECT COUNT(DISTINCT user_id) FROM user_answers 
             WHERE submitted_at >= NOW() - INTERVAL '30 days'`
        );
        const activeUsers = parseInt(activeUsersResult.rows[0].count);

        const answersResult = await pool.query('SELECT COUNT(*) FROM user_answers');
        const totalAnswers = parseInt(answersResult.rows[0].count);

        const usersResult = await pool.query('SELECT id, username, role FROM users');

        const sampleUserId = usersResult.rows.length > 0 ? usersResult.rows[0].id : null;
        let sampleUser = null, lastActive = new Date(), todayStats = { total_sums: 0, correct_sums: 0, wrong_sums: 0, not_attempted: 0 }, answers = [], currentPage = 1, totalPages = 1;
        if (sampleUserId) {
            const userResult = await pool.query('SELECT username, role FROM users WHERE id = $1', [sampleUserId]);
            sampleUser = userResult.rows[0];
            const lastActiveResult = await pool.query(
                `SELECT COALESCE(MAX(submitted_at), NOW()) as last_active 
                 FROM user_answers 
                 WHERE user_id = $1`,
                [sampleUserId]
            );
            lastActive = lastActiveResult.rows[0].last_active || new Date();

            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const todayStatsResult = await pool.query(
                `SELECT 
                    COUNT(DISTINCT question_id) as total_sums,
                    SUM(CASE WHEN is_correct = true THEN 1 ELSE 0 END) as correct_sums,
                    SUM(CASE WHEN is_correct = false AND answer IS NOT NULL THEN 1 ELSE 0 END) as wrong_sums,
                    COUNT(*) - COUNT(CASE WHEN answer IS NOT NULL THEN 1 END) as not_attempted
                 FROM user_answers 
                 WHERE user_id = $1 AND DATE(submitted_at) = $2`,
                [sampleUserId, today.toISOString().split('T')[0]]
            );
            todayStats = todayStatsResult.rows[0] || { total_sums: 0, correct_sums: 0, wrong_sums: 0, not_attempted: 0 };

            const limit = 10;
            const offset = (currentPage - 1) * limit;
            const answersResult = await pool.query(
                `SELECT q.question, ua.answer, ua.is_correct, ua.submitted_at 
                 FROM user_answers ua 
                 JOIN questions q ON ua.question_id = q.id 
                 WHERE ua.user_id = $1 
                 ORDER BY ua.submitted_at DESC 
                 LIMIT $2 OFFSET $3`,
                [sampleUserId, limit, offset]
            );
            const totalAnswersResult = await pool.query(
                'SELECT COUNT(*) FROM user_answers WHERE user_id = $1',
                [sampleUserId]
            );
            const totalAnswersCount = parseInt(totalAnswersResult.rows[0].count);
            totalPages = Math.ceil(totalAnswersCount / limit);
            answers = answersResult.rows;
        }

        res.render('overview', {
            totalModules,
            totalQuestions,
            activeUsers,
            totalAnswers,
            users: usersResult.rows,
            sampleUser,
            lastActive,
            todayStats,
            answers,
            currentPage,
            totalPages
        });
    } catch (err) {
        console.error('Overview fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/add-module', ensureAdminAuthenticated, async (req, res) => {
    const { name, instructions, time_limit } = req.body;
    try {
        await pool.query(
            'INSERT INTO modules (name, instructions, time_limit) VALUES ($1, $2, $3)',
            [name, instructions || null, time_limit ? parseInt(time_limit) * 60 : null]
        );
        res.redirect('/admin');
    } catch (err) {
        console.error('Add module error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/edit-module/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId } = req.params;
    const { name, instructions, time_limit } = req.body;
    try {
        await pool.query(
            'UPDATE modules SET name = $1, instructions = $2, time_limit = $3 WHERE id = $4',
            [name, instructions || null, time_limit ? parseInt(time_limit) * 60 : null, moduleId]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Edit module error:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to edit module' });
    }
});

app.post('/admin/delete-module/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId } = req.params;
    try {
        await pool.query('BEGIN');
        await pool.query('DELETE FROM user_answers WHERE question_id IN (SELECT id FROM questions WHERE module_id = $1)', [moduleId]);
        await pool.query('DELETE FROM questions WHERE module_id = $1', [moduleId]);
        const result = await pool.query('DELETE FROM modules WHERE id = $1 RETURNING *', [moduleId]);
        if (result.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Module not found' });
        }
        await pool.query('COMMIT');
        res.json({ success: true });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Delete module error:', { message: err.message, stack: err.stack, moduleId });
        res.status(500).json({ success: false, message: `Failed to delete module: ${err.message}` });
    }
});

app.get('/admin/questions/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        const questionResult = await pool.query('SELECT * FROM questions WHERE module_id = $1 ORDER BY id', [moduleId]);
        const module = moduleResult.rows[0];
        if (!module) return res.status(404).send('Module not found');
        res.render('questions', { module, questions: questionResult.rows });
    } catch (err) {
        console.error('Questions fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/add-question/:moduleId', ensureAdminAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const { type, question, option_a, option_b, option_c, option_d, option_e, correct_answer_qa, correct_answer_mcq_va, explanation, tags } = req.body;
    const correct_answer = type === 'QA' ? correct_answer_qa : correct_answer_mcq_va;
    if (!type || !question || !correct_answer) return res.status(400).json({ success: false, message: 'Missing required fields' });
    try {
        const result = await pool.query(
            `INSERT INTO questions (module_id, type, question, option_a, option_b, option_c, option_d, option_e, correct_answer, explanation, tags) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
            [moduleId, type, question, option_a || null, option_b || null, option_c || null, option_d || null, option_e || null, correct_answer, explanation || null, tags || null]
        );
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
    if (!type || !question || !correct_answer) return res.status(400).json({ success: false, message: 'Missing required fields' });
    try {
        const result = await pool.query(
            `UPDATE questions SET type = $1, question = $2, option_a = $3, option_b = $4, option_c = $5, option_d = $6, option_e = $7, 
             correct_answer = $8, explanation = $9, tags = $10, version = version + 1 WHERE id = $11 AND module_id = $12 RETURNING id`,
            [type, question, option_a || null, option_b || null, option_c || null, option_d || null, option_e || null, correct_answer, explanation || null, tags || null, questionId, moduleId]
        );
        res.json(result.rowCount > 0 ? { success: true, id: result.rows[0].id } : { success: false, message: 'Question not found' });
    } catch (err) {
        console.error('Edit question error:', err.stack);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/admin/delete-question/:moduleId/:questionId', ensureAdminAuthenticated, async (req, res) => {
    const { moduleId, questionId } = req.params;
    try {
        await pool.query('BEGIN');
        await pool.query('DELETE FROM user_answers WHERE question_id = $1', [questionId]);
        const result = await pool.query('DELETE FROM questions WHERE id = $1 AND module_id = $2 RETURNING *', [questionId, moduleId]);
        if (result.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Question not found' });
        }
        await pool.query('COMMIT');
        res.json({ success: true });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Delete question error:', { message: err.message, stack: err.stack, questionId, moduleId });
        res.status(500).json({ success: false, message: `Failed to delete question: ${err.message}` });
    }
});

app.post('/admin/transfer-question/:questionId', ensureAdminAuthenticated, async (req, res) => {
    const { questionId } = req.params;
    const { targetModuleId, targetType } = req.body;
    if (!targetModuleId || !targetType) return res.status(400).json({ success: false, message: 'Target module and section type required' });
    try {
        await pool.query('BEGIN');
        const moduleCheck = await pool.query('SELECT 1 FROM modules WHERE id = $1', [targetModuleId]);
        if (moduleCheck.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Target module not found' });
        }
        await pool.query('DELETE FROM user_answers WHERE question_id = $1', [questionId]);
        const result = await pool.query(
            'UPDATE questions SET module_id = $1, type = $2 WHERE id = $3 RETURNING *',
            [targetModuleId, targetType, questionId]
        );
        if (result.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Question not found' });
        }
        await pool.query('COMMIT');
        res.json({ success: true, newModuleId: targetModuleId });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Transfer question error:', { message: err.message, stack: err.stack, questionId, targetModuleId, targetType });
        res.status(500).json({ success: false, message: `Failed to transfer question: ${err.message}` });
    }
});

app.post('/admin/transfer-question/batch', ensureAdminAuthenticated, async (req, res) => {
    const { questionIds, targetModuleId, targetType } = req.body;
    if (!questionIds || !Array.isArray(questionIds) || questionIds.length === 0 || !targetModuleId || !targetType) {
        return res.status(400).json({ success: false, message: 'Question IDs, target module, and section type required' });
    }
    try {
        await pool.query('BEGIN');
        const moduleCheck = await pool.query('SELECT 1 FROM modules WHERE id = $1', [targetModuleId]);
        if (moduleCheck.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Target module not found' });
        }
        await pool.query('DELETE FROM user_answers WHERE question_id = ANY($1)', [questionIds]);
        const result = await pool.query(
            'UPDATE questions SET module_id = $1, type = $2 WHERE id = ANY($3) RETURNING *',
            [targetModuleId, targetType, questionIds]
        );
        if (result.rowCount !== questionIds.length) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: `Some questions not found (transferred ${result.rowCount} of ${questionIds.length})` });
        }
        await pool.query('COMMIT');
        res.json({ success: true, newModuleId: targetModuleId, transferredCount: result.rowCount });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Batch transfer question error:', { message: err.message, stack: err.stack, questionIds, targetModuleId, targetType });
        res.status(500).json({ success: false, message: `Failed to transfer questions: ${err.message}` });
    }
});

app.get('/exam/:moduleId', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const userId = req.session.userId;
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        if (moduleResult.rows.length === 0) return res.status(404).send('Module not found');
        const module = moduleResult.rows[0];
        const isExamMode = module.name.startsWith('Exam Mode');

        // Fetch questions with type-based sorting for consistency
        const questionResult = await pool.query(
            'SELECT * FROM questions WHERE module_id = $1 ORDER BY CASE type WHEN \'QA\' THEN 1 WHEN \'MCQ\' THEN 2 WHEN \'VA\' THEN 3 END, id',
            [moduleId]
        );
        const questions = questionResult.rows;
        if (questions.length === 0) return res.send('No questions in this module');

        const answersResult = await pool.query(
            'SELECT question_id, answer FROM user_answers WHERE user_id = $1 AND question_id IN (SELECT id FROM questions WHERE module_id = $2)',
            [userId, moduleId]
        );
        const userAnswers = answersResult.rows;

        const answers = questions.map(q => {
            const userAnswer = userAnswers.find(a => a.question_id === q.id);
            return userAnswer ? userAnswer.answer : null;
        });

        let startIndex = 0;
        let isReviewMode = false;
        if (isExamMode) {
            const submittedResult = await pool.query(
                'SELECT COUNT(DISTINCT question_id) as submitted FROM user_answers WHERE user_id = $1 AND question_id IN (SELECT id FROM questions WHERE module_id = $2)',
                [userId, moduleId]
            );
            isReviewMode = submittedResult.rows[0].submitted >= questions.length;
        } else {
            const lastAnsweredIndex = answers.reduce((max, answer, i) => answer !== null ? i : max, -1);
            startIndex = lastAnsweredIndex + 1 < questions.length ? lastAnsweredIndex + 1 : 0;
            console.log('Normal mode start:', { startIndex, answers, questionIds: questions.map(q => q.id) });
        }

        const currentSection = isExamMode && !isReviewMode ? 'QA' : null;

        res.render('exam', {
            questions,
            module,
            startIndex,
            isExamMode,
            isReviewMode,
            timeLimit: module.time_limit || 2400,
            answers,
            currentSection
        });
    } catch (err) {
        console.error('Exam fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/exam/:moduleId/save-answer', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const { questionId, answer, time_spent } = req.body;
    try {
        const questionResult = await pool.query(
            'SELECT correct_answer, type FROM questions WHERE id = $1 AND module_id = $2',
            [questionId, moduleId]
        );
        if (questionResult.rows.length === 0) return res.status(404).json({ success: false, message: 'Question not found' });
        const { correct_answer, type } = questionResult.rows[0];

        const isCorrect = String(answer).trim() === String(correct_answer).trim();
        if (answer !== null && answer !== '') {
            await pool.query(
                'INSERT INTO user_answers (user_id, question_id, answer, is_correct, time_spent, submitted_at) VALUES ($1, $2, $3, $4, $5, NOW()) ' +
                'ON CONFLICT (user_id, question_id) DO UPDATE SET answer = $3, is_correct = $4, time_spent = $5, submitted_at = NOW()',
                [req.session.userId, questionId, answer, isCorrect, time_spent || 0]
            );
            console.log('Saved:', { userId: req.session.userId, questionId, answer, type });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Save error:', { err: err.stack, questionId, answer });
        res.status(500).json({ success: false, message: 'Failed to save' });
    }
});

app.post('/exam/:moduleId/complete', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const { answers } = req.body;
    console.log('POST /exam/:moduleId/complete hit:', { moduleId, answers });

    if (!Array.isArray(answers)) {
        console.log('Invalid answers format:', answers);
        return res.status(400).json({ success: false, message: 'Invalid answers format: must be an array' });
    }

    try {
        console.log('Starting transaction for module:', moduleId);
        await pool.query('BEGIN');

        for (const { questionId, answer, time_spent } of answers) {
            if (!questionId || typeof time_spent === 'undefined') {
                console.warn(`Skipping invalid entry: questionId=${questionId}, answer=${answer}, time_spent=${time_spent}`);
                continue;
            }

            const questionResult = await pool.query(
                'SELECT correct_answer FROM questions WHERE id = $1 AND module_id = $2',
                [questionId, moduleId]
            );
            if (questionResult.rows.length === 0) {
                console.warn(`Question not found: questionId=${questionId}, moduleId=${moduleId}`);
                continue;
            }
            const correctAnswer = questionResult.rows[0].correct_answer;

            const safeAnswer = answer === undefined || answer === '' ? null : answer;
            const isCorrect = safeAnswer === correctAnswer ? true : (safeAnswer === null ? false : safeAnswer === correctAnswer);
            const safeTimeSpent = Number.isFinite(Number(time_spent)) ? Number(time_spent) : 0;

            console.log(`Processing answer: questionId=${questionId}, answer=${safeAnswer}, time_spent=${safeTimeSpent}`);
            const existingAnswer = await pool.query(
                'SELECT 1 FROM user_answers WHERE user_id = $1 AND question_id = $2',
                [req.session.userId, questionId]
            );

            if (existingAnswer.rowCount > 0) {
                await pool.query(
                    'UPDATE user_answers SET answer = $1, is_correct = $2, time_spent = $3, submitted_at = NOW() WHERE user_id = $4 AND question_id = $5',
                    [safeAnswer, isCorrect, safeTimeSpent, req.session.userId, questionId]
                );
                console.log(`Updated answer for questionId=${questionId}`);
            } else {
                await pool.query(
                    'INSERT INTO user_answers (user_id, question_id, answer, is_correct, time_spent, submitted_at) VALUES ($1, $2, $3, $4, $5, NOW())',
                    [req.session.userId, questionId, safeAnswer, isCorrect, safeTimeSpent]
                );
                console.log(`Inserted answer for questionId=${questionId}`);
            }
        }

        await pool.query('COMMIT');
        console.log('Transaction committed for module:', moduleId);
        res.json({ success: true, redirect: `/exam/${moduleId}/finish` });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Exam completion error:', { message: err.message, stack: err.stack, moduleId, answers });
        res.status(500).json({ success: false, message: `Failed to save exam answers: ${err.message}` });
    }
});

app.get('/exam/:moduleId/finish', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        if (moduleResult.rows.length === 0) return res.status(404).send('Module not found');
        const module = moduleResult.rows[0];
        res.render('exam-complete', { module });
    } catch (err) {
        console.error('Exam finish fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.get('/exam/:moduleId/complete', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const userId = req.session.userId;
    try {
        const moduleResult = await pool.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
        if (moduleResult.rows.length === 0) return res.status(404).send('Module not found');
        const module = moduleResult.rows[0];

        const questionResult = await pool.query('SELECT * FROM questions WHERE module_id = $1 ORDER BY id', [moduleId]);
        const questions = questionResult.rows;

        const answersResult = await pool.query(
            'SELECT question_id, answer FROM user_answers WHERE user_id = $1 AND question_id IN (SELECT id FROM questions WHERE module_id = $2)',
            [userId, moduleId]
        );
        const userAnswers = answersResult.rows;

        const answers = questions.map(q => {
            const userAnswer = userAnswers.find(a => a.question_id === q.id);
            return userAnswer ? userAnswer.answer : null;
        });

        res.render('exam', {
            questions,
            module,
            startIndex: 0,
            isExamMode: false,
            isReviewMode: true,
            timeLimit: module.time_limit || 2400,
            answers,
            currentSection: null
        });
    } catch (err) {
        console.error('Exam complete fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.get('/dashboard', ensureUserAuthenticated, async (req, res) => {
    try {
        const dailySumsResult = await pool.query(
            `SELECT DATE(submitted_at) as date, COUNT(DISTINCT question_id) as count
             FROM user_answers
             WHERE user_id = $1 AND submitted_at >= CURRENT_DATE - INTERVAL '6 days'
             GROUP BY DATE(submitted_at)
             ORDER BY DATE(submitted_at)`,
            [req.session.userId]
        );

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const dailySums = Array(7).fill(0);
        const dailyLabels = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(today.getDate() - i);
            dailyLabels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            const dateStr = date.toISOString().split('T')[0];
            const dayData = dailySumsResult.rows.find(row => row.date.toISOString().split('T')[0] === dateStr);
            dailySums[6 - i] = dayData ? parseInt(dayData.count) : 0;
        }

        const summaryResult = await pool.query(
            `SELECT 
                COUNT(DISTINCT question_id) as total_sums,
                SUM(CASE WHEN is_correct = true THEN 1 ELSE 0 END) as correct_sums,
                SUM(CASE WHEN is_correct = false AND answer IS NOT NULL THEN 1 ELSE 0 END) as wrong_sums
             FROM user_answers
             WHERE user_id = $1`,
            [req.session.userId]
        );
        const summary = summaryResult.rows[0] || { total_sums: 0, correct_sums: 0, wrong_sums: 0 };
        const totalSums = parseInt(summary.total_sums) || 0;
        const correctSums = parseInt(summary.correct_sums) || 0;
        const wrongSums = parseInt(summary.wrong_sums) || 0;

        const moduleStatsResult = await pool.query(
            `SELECT 
                m.id, m.name, 
                COUNT(ua.*) as total_sums,
                SUM(CASE WHEN ua.is_correct = true THEN 1 ELSE 0 END) as correct_sums,
                SUM(CASE WHEN ua.is_correct = false AND ua.answer IS NOT NULL THEN 1 ELSE 0 END) as wrong_sums,
                COUNT(q.*) as total_questions,
                SUM(CASE WHEN ua.is_correct = true THEN 4 
                        WHEN ua.is_correct = false AND ua.answer IS NOT NULL AND q.type IN ('MCQ', 'VA') THEN -1 
                        ELSE 0 END) as score,
                SUM(ua.time_spent) as time_spent
             FROM modules m
             LEFT JOIN questions q ON q.module_id = m.id
             LEFT JOIN user_answers ua ON ua.question_id = q.id AND ua.user_id = $1
             GROUP BY m.id, m.name
             ORDER BY m.id`,
            [req.session.userId]
        );

        const moduleStats = moduleStatsResult.rows.map(row => ({
            id: row.id,
            name: row.name,
            totalSums: parseInt(row.total_sums) || 0,
            correctSums: parseInt(row.correct_sums) || 0,
            wrongSums: parseInt(row.wrong_sums) || 0,
            totalQuestions: parseInt(row.total_questions) || 0,
            score: parseInt(row.score) || 0,
            timeSpent: parseInt(row.time_spent) || 0,
            status: parseInt(row.total_sums) > 0 ? (parseInt(row.total_sums) === parseInt(row.total_questions) ? 'Completed' : 'In Progress') : 'Not Started',
            accuracy: parseInt(row.total_sums) > 0 ? Math.round((parseInt(row.correct_sums) / parseInt(row.total_sums)) * 100) : 0
        }));

        const detailedModuleData = {};
        for (const module of moduleStats) {
            const detailsResult = await pool.query(
                `SELECT q.id, q.question, q.type, q.correct_answer, ua.answer, ua.is_correct, ua.time_spent
                 FROM questions q
                 LEFT JOIN user_answers ua ON ua.question_id = q.id AND ua.user_id = $1
                 WHERE q.module_id = $2
                 ORDER BY q.id`,
                [req.session.userId, module.id]
            );
            detailedModuleData[module.id] = detailsResult.rows;
        }

        const tagsPerformanceResult = await pool.query(
            `SELECT 
                q.tags,
                COUNT(*) as total,
                SUM(CASE WHEN ua.is_correct = true THEN 1 ELSE 0 END) as correct
             FROM user_answers ua
             JOIN questions q ON ua.question_id = q.id
             WHERE ua.user_id = $1 AND q.tags IS NOT NULL
             GROUP BY q.tags`,
            [req.session.userId]
        );

        const tagsPerformance = tagsPerformanceResult.rows.map(row => ({
            tag: row.tags,
            total: parseInt(row.total),
            correct: parseInt(row.correct),
            accuracy: parseInt(row.total) > 0 ? Math.round((parseInt(row.correct) / parseInt(row.total)) * 100) : 0
        }));

        const strengths = tagsPerformance.filter(tag => tag.accuracy >= 75).sort((a, b) => b.accuracy - a.accuracy);
        const weaknesses = tagsPerformance.filter(tag => tag.accuracy < 50).sort((a, b) => a.accuracy - b.accuracy);

        const peerComparisonResult = await pool.query(
            `SELECT 
                m.id, m.name,
                AVG(CASE 
                    WHEN ua.is_correct = true THEN 4 
                    WHEN ua.is_correct = false AND ua.answer IS NOT NULL AND q.type != 'QA' THEN -1 
                    ELSE 0 END) as avg_score
             FROM modules m
             LEFT JOIN questions q ON q.module_id = m.id
             LEFT JOIN user_answers ua ON ua.question_id = q.id
             WHERE ua.user_id != $1
             GROUP BY m.id, m.name
             HAVING COUNT(ua.*) > 0`,
            [req.session.userId]
        );

        const peerComparison = peerComparisonResult.rows.map(row => ({
            id: row.id,
            name: row.name,
            avgScore: parseFloat(row.avg_score).toFixed(1)
        }));

        res.render('dashboard', {
            dailySums,
            dailyLabels,
            totalSums,
            correctSums,
            wrongSums,
            moduleStats,
            detailedModuleData: JSON.stringify(detailedModuleData),
            strengths: strengths.slice(0, 3),
            weaknesses: weaknesses.slice(0, 3),
            peerComparison,
            userId: req.session.userId
        });
    } catch (err) {
        console.error('Dashboard fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/exam/:moduleId/save-answer', ensureUserAuthenticated, async (req, res) => {
    const moduleId = parseInt(req.params.moduleId);
    const { questionId, answer, time_spent } = req.body;
    try {
        const questionResult = await pool.query('SELECT correct_answer FROM questions WHERE id = $1 AND module_id = $2', [questionId, moduleId]);
        if (questionResult.rows.length === 0) return res.status(404).json({ success: false, message: 'Question not found' });
        const correctAnswer = questionResult.rows[0].correct_answer;

        const isCorrect = String(answer).trim() === String(correctAnswer).trim();
        if (answer !== null && answer !== '') {
            await pool.query(
                'INSERT INTO user_answers (user_id, question_id, answer, is_correct, time_spent, submitted_at) VALUES ($1, $2, $3, $4, $5, NOW()) ' +
                'ON CONFLICT (user_id, question_id) DO UPDATE SET answer = $3, is_correct = $4, time_spent = $5, submitted_at = NOW()',
                [req.session.userId, questionId, answer, isCorrect, time_spent || 0]
            );
            console.log('Saved answer:', { userId: req.session.userId, questionId, answer, isCorrect });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Save answer error:', { err: err.stack, questionId, answer });
        res.status(500).json({ success: false, message: 'Failed to save answer' });
    }
});

app.get('/admin/user/:userId', ensureAdminAuthenticated, async (req, res) => {
    const userId = parseInt(req.params.userId);
    try {
        const userResult = await pool.query('SELECT username, role FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];
        if (!user) return res.status(404).send('User not found');

        const lastActiveResult = await pool.query(
            `SELECT COALESCE(MAX(submitted_at), NOW()) as last_active 
             FROM user_answers 
             WHERE user_id = $1`,
            [userId]
        );
        const lastActive = lastActiveResult.rows[0].last_active || new Date();

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayStatsResult = await pool.query(
            `SELECT 
                COUNT(DISTINCT question_id) as total_sums,
                SUM(CASE WHEN is_correct = true THEN 1 ELSE 0 END) as correct_sums,
                SUM(CASE WHEN is_correct = false AND answer IS NOT NULL THEN 1 ELSE 0 END) as wrong_sums,
                COUNT(*) - COUNT(CASE WHEN answer IS NOT NULL THEN 1 END) as not_attempted
             FROM user_answers 
             WHERE user_id = $1 AND DATE(submitted_at) = $2`,
            [userId, today.toISOString().split('T')[0]]
        );
        const todayStats = todayStatsResult.rows[0] || { total_sums: 0, correct_sums: 0, wrong_sums: 0, not_attempted: 0 };

        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const offset = (page - 1) * limit;
        const answersResult = await pool.query(
            `SELECT q.question, ua.answer, ua.is_correct, ua.submitted_at 
             FROM user_answers ua 
             JOIN questions q ON ua.question_id = q.id 
             WHERE ua.user_id = $1 
             ORDER BY ua.submitted_at DESC 
             LIMIT $2 OFFSET $3`,
            [userId, limit, offset]
        );
        const totalAnswersResult = await pool.query(
            'SELECT COUNT(*) FROM user_answers WHERE user_id = $1',
            [userId]
        );
        const totalAnswersCount = parseInt(totalAnswersResult.rows[0].count);
        const totalPages = Math.ceil(totalAnswersCount / limit);

        res.render('user-detail', {
            user,
            lastActive,
            todayStats,
            answers: answersResult.rows,
            currentPage: page,
            totalPages
        });
    } catch (err) {
        console.error('User detail fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.get('/admin/edit-user/:userId', ensureAdminAuthenticated, async (req, res) => {
    const userId = parseInt(req.params.userId);
    try {
        const userResult = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];
        if (!user) return res.status(404).send('User not found');
        res.json(user);
    } catch (err) {
        console.error('Edit user fetch error:', err.stack);
        res.status(500).send('Server error');
    }
});

app.post('/admin/edit-user/:userId', ensureAdminAuthenticated, async (req, res) => {
    const userId = parseInt(req.params.userId);
    const { username, role, password } = req.body;
    try {
        if (!username || !role) {
            return res.status(400).json({ error: 'Username and role are required' });
        }
        let query = 'UPDATE users SET username = $1, role = $2';
        const params = [username, role];
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password = $3';
            params.push(hashedPassword);
        }
        query += ' WHERE id = $4';
        params.push(userId);
        await pool.query(query, params);
        res.json({ success: true });
    } catch (err) {
        console.error('Edit user error:', err.stack);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/admin/delete-user/:userId', ensureAdminAuthenticated, async (req, res) => {
    const userId = parseInt(req.params.userId);
    try {
        await pool.query('BEGIN');
        await pool.query('DELETE FROM user_answers WHERE user_id = $1', [userId]);
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);
        if (result.rowCount === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        await pool.query('COMMIT');
        res.json({ success: true });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Delete user error:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to delete user' });
    }
});

pool.connect().then(() => {
    app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
}).catch((err) => {
    console.error('Failed to connect to database:', err.stack);
    process.exit(1);
});
