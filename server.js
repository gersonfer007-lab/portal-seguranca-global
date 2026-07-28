// ============================================================
// Portal Seguranca Global — Server-Side Security Backend
// ============================================================

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 10000;

// Mercado Pago Configuration (using env secrets)
const MP_ACCESS_TOKEN = process.env.PSG_MP_ACCESS_TOKEN;

// 1. Basic Security & Middlewares
app.use(express.json());
app.use(cors());

// Strict Content Security Policy (CSP)
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://unpkg.com",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://sdk.mercadopago.com",
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: [
        "'self'",
        "data:",
        "blob:",
        "https://*.basemaps.cartocdn.com",
        "https://*.tile.openstreetmap.org",
        "https://*.arcgisonline.com",
        "https://*.googleapis.com",
        "https://*.google.com",
        "https://flagcdn.com",
        "https://upload.wikimedia.org",
        "https://unpkg.com",
        "https://www.mercadopago.com",
      ],
      connectSrc: [
        "'self'",
        "https://viacep.com.br",
        "https://nominatim.openstreetmap.org",
        "https://api.mercadopago.com",
      ],
      frameSrc: [
        "'self'",
        "https://www.google.com",
        "https://maps.google.com",
        "https://earth.google.com",
        "https://www.mercadopago.com",
      ],
      workerSrc: ["'self'", "blob:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// Serve static files from root
app.use(express.static(__dirname));

// 2. Health Check
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// 3. Payment Integration (Mercado Pago)
// Create Preference endpoint for Checkout Pro
app.post('/api/create-preference', async (req, res) => {
  try {
    const { title, unit_price, quantity } = req.body;

    if (!MP_ACCESS_TOKEN) {
      console.error('[Payment] Missing MP_ACCESS_TOKEN');
      return res.status(500).json({ error: 'Payment system not configured' });
    }

    const preference = {
      items: [
        {
          title: title || 'Relatório de Segurança Urbana',
          unit_price: Number(unit_price) || 10.0,
          quantity: Number(quantity) || 1,
          currency_id: 'BRL',
        },
      ],
      back_urls: {
        success: 'https://www.portalsegurancaglobal.com.br?payment=success',
        failure: 'https://www.portalsegurancaglobal.com.br?payment=failure',
        pending: 'https://www.portalsegurancaglobal.com.br?payment=pending',
      },
      auto_return: 'approved',
      statement_descriptor: 'PORTAL SEGURANCA',
    };

    const response = await axios.post(
      'https://api.mercadopago.com/checkout/preferences',
      preference,
      {
        headers: {
          Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.json({ id: response.data.id });
  } catch (error) {
    console.error('[Payment] Error creating preference:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

// 4. Main routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/background-check', (req, res) => {
  res.sendFile(path.join(__dirname, 'background-check.html'));
});

// Catch-all for React-like behavior if needed (optional)
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, 'index.html'));
// });

// Start Server
app.listen(PORT, () => {
  console.log('');
  console.log('==============================================');
  console.log(`  Portal Seguranca Global is LIVE on port ${PORT}`);
  console.log('==============================================');
  console.log('  http://localhost:' + PORT);
  console.log('');
});
