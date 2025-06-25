const express = require('express');

module.exports = function (pool, authenticateToken) {
  const router = express.Router();

  // GET all public + own writeups
  router.get('/', authenticateToken, async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT w.*, u.name AS author_name
        FROM writeups w
        JOIN users u ON w.user_id = u.id
        WHERE w.is_public = TRUE OR w.user_id = $1
        ORDER BY w.created_at DESC
      `, [req.user.id]);
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Get my claimed bottles
  router.get('/myclaims', authenticateToken, async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT w.* FROM writeups w WHERE w.claimed_by = $1 ORDER BY w.created_at DESC`,
        [req.user.id]
      );
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Create new writeup
  router.post('/', authenticateToken, async (req, res) => {
    const { title, content, is_public } = req.body;
    try {
      const result = await pool.query(
        `INSERT INTO writeups (user_id, title, content, is_public, created_at, likes)
         VALUES ($1, $2, $3, $4, NOW(), 0)
         RETURNING *`,
        [req.user.id, title, content, is_public]
      );
      res.status(201).json(result.rows[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Like a writeup
  router.post('/:id/like', authenticateToken, async (req, res) => {
    const writeupId = req.params.id;
    try {
      const result = await pool.query("SELECT likes FROM writeups WHERE id = $1", [writeupId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Bottle Empty' });

      const newLikes = result.rows[0].likes + 1;
      await pool.query("UPDATE writeups SET likes = $1 WHERE id = $2", [newLikes, writeupId]);

      res.json({ likes: newLikes });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Unlike a writeup
  router.post('/:id/unlike', authenticateToken, async (req, res) => {
    const writeupId = req.params.id;
    try {
      const result = await pool.query("SELECT likes FROM writeups WHERE id = $1", [writeupId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Bottle Empty' });

      const newLikes = Math.max(0, result.rows[0].likes - 1);
      await pool.query("UPDATE writeups SET likes = $1 WHERE id = $2", [newLikes, writeupId]);

      res.json({ likes: newLikes });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Claim a bottle
  router.post('/claim/:id', authenticateToken, async (req, res) => {
    const writeupId = req.params.id;
    const userId = req.user.id;
    try {
      const result = await pool.query("SELECT * FROM writeups WHERE id = $1", [writeupId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Bottle Empty' });

      if (result.rows[0].claimed_by) {
        return res.status(400).json({ error: 'Already claimed by someone else.' });
      }

      await pool.query("UPDATE writeups SET claimed_by = $1 WHERE id = $2", [userId, writeupId]);
      res.json({ message: 'Bottle claimed successfully!' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Unclaim a bottle
  router.post('/unclaim/:id', authenticateToken, async (req, res) => {
    const writeupId = req.params.id;
    const userId = req.user.id;
    try {
      const result = await pool.query("SELECT claimed_by FROM writeups WHERE id = $1", [writeupId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Bottle Empty' });

      if (result.rows[0].claimed_by !== userId) {
        return res.status(403).json({ error: 'You can only unclaim your own claimed bottles' });
      }

      await pool.query("UPDATE writeups SET claimed_by = NULL WHERE id = $1", [writeupId]);
      res.json({ message: 'Bottle thrown back to sea!' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete own writeup
  router.delete('/:id', authenticateToken, async (req, res) => {
    const writeupId = req.params.id;

    try {
      const result = await pool.query("SELECT user_id FROM writeups WHERE id = $1", [writeupId]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Writeup not found' });
      }
      if (result.rows[0].user_id !== req.user.id) {
        return res.status(403).json({ error: 'Unauthorized to delete this writeup' });
      }

      await pool.query("DELETE FROM writeups WHERE id = $1", [writeupId]);
      res.json({ message: 'Writeup deleted successfully' });

    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  return router;
}
