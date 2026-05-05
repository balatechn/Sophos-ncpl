const express = require('express');
const router = express.Router();
const axios = require('axios');
const NodeCache = require('node-cache');

const cache = new NodeCache({ stdTTL: parseInt(process.env.CACHE_TTL) || 120 });

let tokenCache = { token: null, expiry: 0 };

async function getSophosToken() {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.expiry) {
    return tokenCache.token;
  }

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: process.env.SOPHOS_CLIENT_ID,
    client_secret: process.env.SOPHOS_CLIENT_SECRET,
    scope: 'token',
  });

  const response = await axios.post(process.env.SOPHOS_AUTH_URL, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  tokenCache.token = response.data.access_token;
  tokenCache.expiry = now + (response.data.expires_in - 60) * 1000;
  return tokenCache.token;
}

async function sophosGet(path, params = {}) {
  const cacheKey = path + JSON.stringify(params);
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const token = await getSophosToken();
  const response = await axios.get(`${process.env.SOPHOS_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'X-Tenant-ID': process.env.SOPHOS_TENANT_ID,
    },
    params,
  });

  cache.set(cacheKey, response.data);
  return response.data;
}

async function sophosDelete(path) {
  const token = await getSophosToken();
  const response = await axios.delete(`${process.env.SOPHOS_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'X-Tenant-ID': process.env.SOPHOS_TENANT_ID,
    },
  });
  cache.flushAll();
  return response.data;
}

// ── Dashboard summary ────────────────────────────────────────────────────────
router.get('/summary', async (req, res) => {
  try {
    const [endpoints, alerts, admins] = await Promise.all([
      sophosGet('/endpoint/v1/endpoints', { pageSize: 500 }),
      sophosGet('/common/v1/alerts', { pageSize: 100 }),
      sophosGet('/common/v1/admins', { pageSize: 100 }),
    ]);

    const eps = endpoints.items || [];
    const als = alerts.items || [];

    const summary = {
      totalEndpoints: eps.length,
      healthy: eps.filter(e => e.health?.overall === 'good').length,
      suspicious: eps.filter(e => e.health?.overall === 'suspicious').length,
      bad: eps.filter(e => e.health?.overall === 'bad').length,
      tamperOff: eps.filter(e => e.tamperProtectionEnabled === false).length,
      totalAlerts: als.length,
      highAlerts: als.filter(a => a.severity === 'high').length,
      mediumAlerts: als.filter(a => a.severity === 'medium').length,
      lowAlerts: als.filter(a => a.severity === 'low').length,
      totalAdmins: (admins.items || []).length,
      osSummary: eps.reduce((acc, e) => {
        const os = e.os?.platform || 'unknown';
        acc[os] = (acc[os] || 0) + 1;
        return acc;
      }, {}),
    };
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Endpoints ────────────────────────────────────────────────────────────────
router.get('/endpoints', async (req, res) => {
  try {
    const data = await sophosGet('/endpoint/v1/endpoints', { pageSize: 500 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/endpoints/:id', async (req, res) => {
  try {
    const data = await sophosGet(`/endpoint/v1/endpoints/${req.params.id}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/endpoints/:id', async (req, res) => {
  try {
    await sophosDelete(`/endpoint/v1/endpoints/${req.params.id}`);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Endpoint installed software ──────────────────────────────────────────────
router.get('/endpoints/:id/installed-software', async (req, res) => {
  try {
    const data = await sophosGet(`/endpoint/v1/endpoints/${req.params.id}/installed-software`, { pageSize: 200 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Alerts ───────────────────────────────────────────────────────────────────
router.get('/alerts', async (req, res) => {
  try {
    const data = await sophosGet('/common/v1/alerts', { pageSize: 500 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Admins ───────────────────────────────────────────────────────────────────
router.get('/admins', async (req, res) => {
  try {
    const data = await sophosGet('/common/v1/admins', { pageSize: 100 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/admins/:id', async (req, res) => {
  try {
    await sophosDelete(`/common/v1/admins/${req.params.id}`);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Threats (detections) ─────────────────────────────────────────────────────
router.get('/threats', async (req, res) => {
  try {
    const data = await sophosGet('/endpoint/v1/threats', { pageSize: 200 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
